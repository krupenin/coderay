module CodeRay
module Scanners
  # Scanner for the 1C:Enterprise query language https://en.wikipedia.org/wiki/1C_Company
  # 1C:Enterprise is a market leader in Russia. 
  # http://1c-dn.com/1c_enterprise/what_is_1c_enterprise/
  # Josh Goebel (SQL) -> 1C by romix.  

  class Rus1c_SQL < Scanner
    
    register_for :rus1c_sql
    
    KEYWORDS = %w(AND И OR  ИЛИ IN  В IN HIERARCHY  В ИЕРАРХИИ NOT НЕ BETWEEN МЕЖДУ LIKE  ПОДОБНО ESCAPE  СПЕЦСИМВОЛ NULL  IS  ЕСТЬ 
 CASE  ВЫБОР WHEN  КОГДА THEN  ТОГДА ELSE  ИНАЧЕ END КОНЕЦ  CAST  ВЫРАЗИТЬ TRUE  ИСТИНА  FALSE ЛОЖЬ REFS  ССЫЛКА
   UNDEFINED НЕОПРЕДЕЛЕНО DAY ДЕНЬ  HOUR  ЧАС MINUTE  МИНУТА  MONTH МЕСЯЦ QUARTER КВАРТАЛ SECOND  
  СЕКУНДА WEEK  НЕДЕЛЯ  YEAR  ГОД TENDAYS ДЕКАДА  HALFYEAR  ПОЛУГОДИЕ 
    )
    
    OBJECTS = %w(
      database databases table tables column columns fields index constraint
      constraints transaction function procedure row key view trigger
    )
    
    COMMANDS = %w(
SELECT  ВЫБРАТЬ FROM  ИЗ  WHERE ГДЕ 
ORDER УПОРЯДОЧИТЬ ORDER BY  УПОРЯДОЧИТЬ ПО  BY  ПО  ON  DESC  УБЫВ  
HIERARCHY ИЕРАРХИЯ  ONLY HIERARCHY  ТОЛЬКО ИЕРАРХИЯ GROUP СГРУППИРОВАТЬ GROUP BY  
СГРУППИРОВАТЬ ПО  DISTINCT  РАЗЛИЧНЫЕ   TOP ПЕРВЫЕ    HAVING  ИМЕЮЩИЕ 
LEFT  ЛЕВОЕ RIGHT ПРАВОЕ  FULL  ПОЛНОЕ  INNER ВНУТРЕННЕЕ  JOIN  СОЕДИНЕНИЕ  
UNION ОБЪЕДИНИТЬ  ALL ВСЕ 
NUMBER  ЧИСЛО BOOLEAN БУЛЕВО  STRING  СТРОКА  DATE  ДАТА  AS  КАК 
TOTALS  ИТОГИ OVERALL ОБЩИЕ AUTOORDER АВТОУПОРЯДОЧИВАНИЕ PERIODS ПЕРИОДАМИ
  FOR ДЛЯ UPDATE  ИЗМЕНЕНИЯ ALLOWED РАЗРЕШЕННЫЕ 
 INTO  ПОМЕСТИТЬ DROP  УНИЧТОЖИТЬ  INDEX ИНДЕКСИРОВАТЬ INDEX BY  ИНДЕКСИРОВАТЬ ПО  
  VALUE ЗНАЧЕНИЕ  VALUETYPE ТИПЗНАЧЕНИЯ TYPE  ТИП CHARACTERISTICS ХАРАКТЕРИСТИКИ  
  CHARACTERISTICTYPES ВИДЫХАРАКТЕРИСТИК LIST  СПИСОК  KEYFIELD  ПОЛЕКЛЮЧА ID  
  ИДЕНТИФИКАТОР NAMEFIELD ПОЛЕИМЕНИ NAME  ИМЯ VALUETYPEFIELD  ПОЛЕТИПАЗНАЧЕНИЯ  
  CHARACTERISTICVALUES  ЗНАЧЕНИЯХАРАКТЕРИСТИК VALUES  ЗНАЧЕНИЯ  OBJECTFIELD ПОЛЕОБЪЕКТА 
  OBJECT  ОБЪЕКТ TYPEFIELD ПОЛЕВИДА  CHARACTERISTIC  ХАРАКТЕРИСТИКА  VALUEFIELD  ПОЛЕЗНАЧЕНИЯ 
    )
    
    PREDEFINED_TYPES = %w(
      char varchar varchar2 enum binary text tinytext mediumtext
      longtext blob tinyblob mediumblob longblob timestamp
      date time datetime year double decimal float int
      integer tinyint mediumint bigint smallint unsigned bit
      bool boolean hex bin oct
    )
    
    PREDEFINED_FUNCTIONS = %w( sum cast substring abs pi count min max avg now )
    
    DIRECTIVES = %w( 
      auto_increment unique default charset initially deferred
      deferrable cascade immediate read write asc desc after
      primary foreign return engine
    )
    
    PREDEFINED_CONSTANTS = %w( null true false )
    
    IDENT_KIND = WordList::CaseIgnoring.new(:ident).
      add(KEYWORDS, :keyword).
      add(OBJECTS, :type).
      add(COMMANDS, :class).
      add(PREDEFINED_TYPES, :predefined_type).
      add(PREDEFINED_CONSTANTS, :predefined_constant).
      add(PREDEFINED_FUNCTIONS, :predefined).
      add(DIRECTIVES, :directive)
    
    ESCAPE = / [rbfntv\n\\\/'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} | . /mx
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x
    
    STRING_PREFIXES = /[xnb]|_\w+/i
    
    def scan_tokens encoder, options
      
      state = :initial
      string_type = nil
      string_content = ''
      name_expected = false
      
      until eos?
        
        if state == :initial
          
          if match = scan(/ \s+ | \\\n /x)
            encoder.text_token match, :space
          
          elsif match = scan(/(?:\/\/\s?|#).*/)
            encoder.text_token match, :comment
            
          elsif match = scan(%r( /\* (!)? (?: .*? \*/ | .* ) )mx)
            encoder.text_token match, self[1] ? :directive : :comment
            
          elsif match = scan(/ [*\/=<>:;,!&^|()\[\]{}~%] | [-+\.](?!\d) /x)
            name_expected = true if match == '.' && check(/[A-Za-z_]/)
            encoder.text_token match, :operator
            
          elsif match = scan(/(#{STRING_PREFIXES})?([`"'])/o)
            prefix = self[1]
            string_type = self[2]
            encoder.begin_group :string
            encoder.text_token prefix, :modifier if prefix
            match = string_type
            state = :string
            encoder.text_token match, :delimiter
            
          elsif match = scan(/ @? [A-Za-zА-Яа-я_][A-Za-zА-Яа-я_0-9]* /x)
            encoder.text_token match, name_expected ? :ident : (match[0] == ?@ ? :variable : IDENT_KIND[match])
            name_expected = false
            
          elsif match = scan(/0[xX][0-9A-Fa-f]+/)
            encoder.text_token match, :hex
            
          elsif match = scan(/0[0-7]+(?![89.eEfF])/)
            encoder.text_token match, :octal
            
          elsif match = scan(/[-+]?(?>\d+)(?![.eEfF])/)
            encoder.text_token match, :integer
            
          elsif match = scan(/[-+]?(?:\d[fF]|\d*\.\d+(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)/)
            encoder.text_token match, :float
          
          elsif match = scan(/\\N/)
            encoder.text_token match, :predefined_constant
            
          else
            encoder.text_token getch, :error
            
          end
          
        elsif state == :string
          if match = scan(/[^\\"'`]+/)
            string_content << match
            next
          elsif match = scan(/["'`]/)
            if string_type == match
              if peek(1) == string_type  # doubling means escape
                string_content << string_type << getch
                next
              end
              unless string_content.empty?
                encoder.text_token string_content, :content
                string_content = ''
              end
              encoder.text_token match, :delimiter
              encoder.end_group :string
              state = :initial
              string_type = nil
            else
              string_content << match
            end
          elsif match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            unless string_content.empty?
              encoder.text_token string_content, :content
              string_content = ''
            end
            encoder.text_token match, :char
          elsif match = scan(/ \\ . /mox)
            string_content << match
            next
          elsif match = scan(/ \\ | $ /x)
            unless string_content.empty?
              encoder.text_token string_content, :content
              string_content = ''
            end
            encoder.text_token match, :error unless match.empty?
            encoder.end_group :string
            state = :initial
          else
            raise "else case \" reached; %p not handled." % peek(1), encoder
          end
          
        else
          raise 'else-case reached', encoder
          
        end
        
      end
      
      if state == :string
        encoder.end_group state
      end
      
      encoder
      
    end
    
  end
  
end
end
