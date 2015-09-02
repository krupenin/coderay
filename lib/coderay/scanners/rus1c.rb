module CodeRay
module Scanners

  # Scanner for the 1C:Enterprise language https://en.wikipedia.org/wiki/1C_Company
  # 1C:Enterprise is a market leader in Russia.
  # http://1c-dn.com/1c_enterprise/what_is_1c_enterprise/
  # Delphi -> 1C by romix.

  class Rus1c < Scanner

    register_for :rus1c
    file_extension '1c'

    KEYWORDS = ['If', 'Если', 'Then', 'Тогда', 'ElsIf', 'ИначеЕсли', 'Else', 'Иначе', 'EndIf', 'КонецЕсли',
'Do', 'Цикл', 'For', 'Для', 'To', 'По', 'по', 'Each', 'Каждого', 'In', 'Из', 'из', 'While', 'Пока', 'EndDo', 'КонецЦикла',
'Procedure', 'Процедура', 'EndProcedure', 'КонецПроцедуры', 'Function', 'Функция', 'EndFunction', 'КонецФункции',
'Var', 'Перем', 'Export', 'Экспорт', 'Goto', 'Перейти', 'And', 'И', 'и', 'Or', 'Или', 'или', 'Not', 'Не', 'не', 'Знач',
'Break', 'Прервать', 'Continue', 'Продолжить', 'Return', 'Возврат',
'Try', 'Попытка', 'Except', 'Исключение', 'EndTry', 'КонецПопытки', 'Raise', 'ВызватьИсключение',
'False', 'Ложь', 'True', 'Истина', 'Undefined', 'Неопределено', 'Null', 'New', 'Новый',
'Execute', 'Выполнить', 'AddHandler', 'ДобавитьОбработчик', 'RemoveHandler', 'УдалитьОбработчик',
    ]  # :nodoc:

    DIRECTIVES = ['&НаКлиенте', '&НаСервере',

    ]  # :nodoc:

    IDENT_KIND = WordList::CaseIgnoring.new(:ident).
      add(KEYWORDS, :keyword1c).
      add(DIRECTIVES, :directive)  # :nodoc:

    NAME_FOLLOWS = WordList::CaseIgnoring.new(false).
      add(%w(procedure function .))  # :nodoc:

  protected

    def scan_tokens encoder, options

      state = :initial
      last_token = ''

      until eos?

        if state == :initial

          if match = scan(/ \s+ /x)
            encoder.text_token match, :space
            next

          elsif match = scan(/ \# [^\n]* /x)
            encoder.text_token match, :preprocessor
            next

          elsif match = scan(/ \& [^\n]+ /x)
            encoder.text_token match, :comment
            next


          elsif match = scan(%r! // [^\n]*  !mx)
            encoder.text_token match, :comment
            next

          elsif match = scan(/ <[>=]? | >=? | :=? | [-+=*\/;,\?\:\%|\(\)\[\]]   /x)
            encoder.text_token match, :operator


          elsif match = scan(/ [A-Za-z_А-Яа-я\#\&][A-Za-zА-Яа-я_0-9]* /x)
            encoder.text_token match, NAME_FOLLOWS[last_token] ? :ident : IDENT_KIND[match]


          elsif match = scan(/ " /x)
            encoder.begin_group :string
            encoder.text_token match, :delimiter
            state = :string


          elsif match = scan(/ (?: \d+ )  /x)
            encoder.text_token match, :integer

          elsif match = scan(/ \d+ \. \d+ /x)
            encoder.text_token match, :float

          else
            encoder.text_token getch, :error
            next

          end

        elsif state == :string
          if match = scan(/[^\"]+/)
            encoder.text_token match, :content
          elsif match = scan(/""/)
            encoder.text_token match, :char
          elsif match = scan(/"/)
            encoder.text_token match, :delimiter
            encoder.end_group :string
            state = :initial
            next
 #         elsif match = scan(/\n/)
 #           encoder.end_group :string
 #           encoder.text_token match, :space
 #           state = :initial
          else
            raise "else case \' reached; %p not handled." % peek(1), encoder
          end

        else
          raise 'else-case reached', encoder

        end

        last_token = match

      end

      if state == :string
        encoder.end_group state
      end

      encoder
    end

  end

end
end
