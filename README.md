# QuerySign
Подписание ЭЦП по ГОСТ 2012 с помощью КриптоПро JCP 2.*. Подписывает присоединенную и отсоединнную подпись. Позволяет подписывать XML по правилам СМЭВ.

*Java 1.8 JDK openlogic-openjdk-8u372-b07 Spring 5.3.28 Java JCP 2.0 */   
**Не забыть проинжектить JDK с помощью Java JCP 2.0**

Точка входа в приложение - [Вот она](https://github.com/disant9807/QuerySign/blob/master/server/src/main/java/ru/spandco/querysign/server/ServerApplication.java)

### Модули
- Server - Логика сервиса. Сборка Maven в рабочей директории querysign(root) *clean compile package -Dmaven.test.skip*
- QueryProxy - Модуль прокси для связи в других сервисах с текущим. Сборка Maven в директории QueryProxy *clean compile package install -Dmaven.test.skip*

### Сборка
Выполнить команду мавен *clean compile package -Dmaven.test.skip* в директории root. После этого запускать server-internal.jar
