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
https://b24-3h758z.bitrix24.pl/
nmap -sn 192.168.68.0/24 -oG nmap_output


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
