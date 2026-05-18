# Intrebari si raspunsuri pentru proiectul Argus

## Intrebari generale

1. **Care este scopul principal al proiectului Argus?**  
   Scopul proiectului este sa ofere o platforma locala de securitate pentru monitorizare, scanare antivirus, firewall, filtrare web si analiza de amenintari.

2. **Ce problema incearca sa rezolve aplicatia?**  
   Aplicatia rezolva problema administrarii fragmentate a securitatii, adunand mai multe functii intr-un singur dashboard.

3. **Cine ar putea folosi aceasta platforma?**  
   Poate fi folosita de un utilizator avansat, administrator de sistem, student sau persoana care vrea sa testeze concepte de securitate informatica.

4. **Care sunt modulele principale ale aplicatiei?**  
   Modulele principale sunt Dashboard, Platform, Cleanup, Firewall, Filtering, Protection, MITRE ATT&CK, Geo Tracking, Memory Scan, Threat Intel, Events si Controls.

5. **De ce ai ales o aplicatie web pentru o platforma de securitate locala?**  
   O aplicatie web este usor de folosit, permite o interfata vizuala moderna si separa clar partea de prezentare de logica backend.

6. **Ce inseamna numele Argus in contextul proiectului?**  
   Argus sugereaza supraveghere si atentie continua, ceea ce se potriveste cu ideea unei platforme care monitorizeaza securitatea sistemului.

7. **Care este avantajul unui dashboard centralizat?**  
   Utilizatorul vede rapid starea sistemului, alertele, scanarile si politicile active fara sa acceseze separat mai multe instrumente.

8. **Ce tip de aplicatie este proiectul?**  
   Este o aplicatie full-stack, cu frontend in React si backend in Node.js/Express.

9. **Ce functionalitate consideri cea mai importanta?**  
   Modulul de protectie este foarte important, deoarece combina scanarea locala cu analiza euristica si servicii externe.

10. **Ce face proiectul diferit fata de un simplu antivirus?**  
    Proiectul nu se limiteaza la scanarea fisierelor, ci include firewall, filtrare de continut, threat intelligence, MITRE, alerte live si monitorizare de sistem.

## Arhitectura si tehnologii

11. **Cum este impartit proiectul intre frontend si backend?**  
    Frontend-ul este in folderul `frontend`, iar backend-ul este in folderul `backend`.

12. **Ce rol are backend-ul?**  
    Backend-ul gestioneaza API-urile, scanarile, regulile, rapoartele, proxy-ul local, datele de securitate si integrarea cu servicii externe.

13. **Ce rol are frontend-ul?**  
    Frontend-ul afiseaza datele si ofera utilizatorului controale pentru modulele aplicatiei.

14. **Cum comunica frontend-ul cu backend-ul?**  
    Comunicarea se face prin cereri HTTP catre API si prin WebSocket pentru alerte live.

15. **Ce porturi foloseste aplicatia?**  
    Backend-ul ruleaza pe `localhost:5000`, iar frontend-ul ruleaza pe `localhost:5173`.

16. **De ce ai folosit Node.js si Express?**  
    Node.js si Express permit construirea rapida a unui API modular si se integreaza bine cu operatii pe fisiere, retea si procese.

17. **De ce ai folosit React si Vite?**  
    React permite construirea interfetei pe componente, iar Vite ofera pornire si build rapid pentru dezvoltare.

18. **Ce rol are fisierul `server.js`?**  
    `server.js` porneste backend-ul, configureaza Express, monteaza rutele API, porneste WebSocket-ul si initializeaza proxy-ul local.

19. **Ce rol are scriptul `start-platform.ps1`?**  
    Scriptul porneste platforma pe Windows, instaleaza dependinte lipsa, pregateste configuratia si lanseaza backend-ul si frontend-ul.

20. **De ce sunt separate rutele in fisiere diferite?**  
    Separarea rutelor face codul mai usor de inteles, mentinut si extins.

## Functionalitati principale

21. **Ce afiseaza dashboard-ul principal?**  
    Dashboard-ul afiseaza starea sistemului, utilizarea CPU/RAM, reteaua, numarul de scanari, alerte si statusul modulelor.

22. **Cum functioneaza modulul de antivirus?**  
    Modulul analizeaza fisiere prin semnaturi, reguli YARA, euristici, IOC-uri si optional servicii externe precum Hybrid Analysis.

23. **Ce este carantina?**  
    Carantina este o zona in care fisierele suspecte sunt izolate pentru a nu fi folosite accidental.

24. **Cum functioneaza scanarea fisierelor?**  
    Backend-ul primeste fisierele, calculeaza hash-ul, verifica semnaturi, aplica reguli euristice si intoarce un verdict.

25. **Ce este testul EICAR?**  
    EICAR este un fisier standard de test folosit pentru verificarea detectiei antivirus fara a folosi malware real.

26. **Cum functioneaza filtrarea de continut?**  
    Filtrarea se face printr-un proxy local care verifica domeniile accesate si blocheaza domeniile din listele selectate.

27. **Ce categorii pot fi blocate?**  
    Pot fi blocate categorii precum adult, ads, malware, gambling, piracy, social media si domenii custom.

28. **Ce rol are proxy-ul local?**  
    Proxy-ul local intercepteaza cererile browserului si blocheaza destinatiile care apar in politica de filtrare.

29. **Cum functioneaza firewall-ul?**  
    Modulul firewall gestioneaza reguli de permitere sau blocare a traficului si afiseaza sumarul regulilor active.

30. **Ce face modulul de geo-filtering?**  
    Geo-filtering-ul verifica IP-uri si conexiuni, le asociaza cu tari si permite blocarea anumitor zone geografice.

31. **Ce este Threat Intelligence?**  
    Threat Intelligence inseamna colectarea si agregarea indicatorilor de amenintare precum hash-uri, domenii, IP-uri si tehnici MITRE.

32. **Ce rol are integrarea cu Hybrid Analysis/Falcon Sandbox?**  
    Integrarea permite trimiterea fisierelor sau URL-urilor catre un serviciu extern pentru analiza mai detaliata.

33. **Ce sunt regulile YARA?**  
    Regulile YARA sunt reguli text care cauta modele suspecte in fisiere, cum ar fi string-uri, hex pattern-uri sau conditii logice.

34. **Ce face modulul Memory Scan?**  
    Memory Scan analizeaza procesele active si cauta semne de comportament suspect, cai neobisnuite sau argumente obfuscate.

35. **Ce rol are pagina MITRE ATT&CK?**  
    Pagina MITRE arata tehnicile de atac detectate si le organizeaza dupa tactici, ajutand la intelegerea tipului de amenintare.

## Securitate

36. **Cum este protejata cheia API pentru Hybrid Analysis?**  
    Cheia poate fi mutata intr-un fisier criptat, iar parola locala ramane doar pe masina utilizatorului.

37. **De ce nu este bine ca o cheie API sa fie scrisa direct in cod?**  
    O cheie scrisa direct in cod poate fi publicata accidental si folosita abuziv de alte persoane.

38. **Ce rol are autentificarea cu token?**  
    Token-ul protejeaza endpoint-urile API si permite accesul doar sesiunilor autorizate.

39. **Ce se intampla daca backend-ul nu este disponibil?**  
    Frontend-ul afiseaza o eroare, iar datele si actiunile care depind de API nu mai functioneaza.

40. **Care sunt riscurile unei aplicatii care modifica setari de proxy sau firewall?**  
    Poate bloca trafic legitim sau poate afecta conexiunea la internet daca regulile sunt configurate gresit.

41. **De ce este importanta allowlist-ul in content filtering?**  
    Allowlist-ul permite exceptarea domeniilor legitime care nu trebuie blocate chiar daca apar in listele generale.

42. **De ce este utila separarea pe roluri, cum ar fi admin?**  
    Separarea pe roluri impiedica utilizatorii obisnuiti sa execute actiuni sensibile, cum ar fi resetari sau stergeri.

43. **Ce inseamna principiul least privilege?**  
    Inseamna ca o componenta sau un utilizator trebuie sa aiba doar permisiunile strict necesare pentru actiunea respectiva.

44. **Ce masuri exista impotriva accesului neautorizat?**  
    Exista token-uri de sesiune, verificare pentru request-uri locale si middleware pentru roluri.

45. **De ce trebuie protejat fisierul `.env`?**  
    Fisierul `.env` poate contine parole, chei API si setari sensibile, deci nu trebuie publicat in repository.

## Implementare

46. **Cum sunt organizate rutele API in backend?**  
    Rutele sunt separate pe module: `auth`, `status`, `stats`, `firewall`, `antivirus`, `contentFilter`, `geoFilter`, `intelligence` si altele.

47. **Cum sunt salvate regulile firewall si content filter?**  
    Regulile sunt salvate local in fisiere sau store-uri dedicate, de obicei sub forma de JSON.

48. **Cum sunt generate alertele live?**  
    Backend-ul trimite evenimente prin WebSocket, iar frontend-ul le afiseaza in timp real.

49. **De ce se foloseste WebSocket?**  
    WebSocket permite transmiterea alertelor live fara refresh manual si fara polling constant.

50. **Cum sunt colectate informatiile despre CPU, RAM si retea?**  
    Sunt colectate cu libraria `systeminformation` si, unde este nevoie, cu ajutorul comenzilor de sistem.

51. **Cum se genereaza raportul PDF?**  
    Raportul este generat in backend folosind libraria `pdfkit`.

52. **Cum functioneaza scanarea memoriei si a proceselor?**  
    Backend-ul enumera procesele active, verifica informatii precum nume, cale, parinte si argumente si aplica reguli de suspiciune.

53. **Cum sunt mapate detectiile la MITRE ATT&CK?**  
    Semnalele detectate sunt asociate cu tehnici MITRE, astfel incat rezultatul sa explice ce tip de comportament de atac a fost observat.

54. **Ce rol are `multer` in proiect?**  
    `multer` este folosit pentru upload-ul fisierelor care trebuie scanate.

55. **Ce rol are `axios` in proiect?**  
    `axios` este folosit pentru cereri HTTP catre servicii externe, cum ar fi MalwareBazaar sau Hybrid Analysis.

56. **Ce rol are `cors`?**  
    `cors` permite frontend-ului sa comunice cu backend-ul chiar daca ruleaza pe un port diferit.

57. **Ce rol are `dotenv`?**  
    `dotenv` incarca variabile de configurare din fisierul `.env`.

58. **Ce inseamna API REST in contextul proiectului?**  
    API-ul REST expune endpoint-uri HTTP pentru actiuni precum scanare, citire reguli, actualizare politici si obtinere statistici.

59. **De ce foloseste proiectul fisiere JSON pentru unele date?**  
    Fisierele JSON sunt simple, usor de citit si suficiente pentru un proiect local fara baza de date complexa.

60. **Ce avantaj are impartirea codului in `routes`, `utils`, `store` si `middleware`?**  
    Aceasta impartire separa responsabilitatile: rutele primesc cereri, utilitarele contin logica, store-urile tin date, iar middleware-ul verifica accesul.

## Testare si limitari

61. **Ce teste exista in proiect?**  
    Exista teste pentru configurare, memory scanner, Hybrid Analysis, semnaturi hex, scor euristic, geo-filter, content-filter si analysis store.

62. **Cum ai verifica daca antivirusul detecteaza corect un fisier suspect?**  
    As testa cu fisierul EICAR si cu fisiere controlate care contin semnaturi sau string-uri cunoscute.

63. **Ce limitari are scanarea euristica?**  
    Poate produce fals pozitive sau fals negative, deoarece estimeaza riscul pe baza unor tipare, nu pe certitudine absoluta.

64. **Ce functionalitati depind de Windows?**  
    Configurarea WinINET pentru proxy, unele comenzi de sistem si unele actiuni legate de firewall sau cleanup sunt specifice Windows.

65. **Ce se intampla daca aplicatia nu are permisiuni suficiente?**  
    Unele actiuni pot esua, de exemplu modificarea regulilor firewall sau accesarea unor informatii de sistem.

66. **Ce ai imbunatati pe viitor?**  
    As adauga utilizatori multipli, baza de date, audit log mai detaliat, reguli mai robuste si integrare cloud.

67. **Care este cea mai complexa parte a proiectului?**  
    Cea mai complexa parte este combinarea scanarii locale cu servicii externe si afisarea unui verdict clar pentru utilizator.

68. **Cum ai testa modulul de content filtering?**  
    As activa categorii, as adauga domenii custom, as folosi allowlist si as verifica daca proxy-ul blocheaza corect domeniile.

69. **Cum ai testa WebSocket-ul?**  
    As genera un eveniment de scanare sau alerta si as verifica daca apare imediat in interfata.

70. **Care este o limitare a folosirii fisierelor locale in locul unei baze de date?**  
    Fisierele locale sunt simple, dar nu sunt ideale pentru multi utilizatori, volum mare de date sau interogari complexe.

## Intrebari mai grele

71. **Care este diferenta dintre scanarea locala si scanarea prin sandbox extern?**  
    Scanarea locala este mai rapida si pastreaza fisierul pe masina, iar sandbox-ul extern ofera analiza mai profunda, dar necesita API si poate trimite fisierul in afara sistemului.

72. **De ce o detectie euristica poate produce fals pozitive?**  
    Pentru ca unele programe legitime pot contine string-uri, comenzi sau comportamente asemanatoare cu cele folosite de malware.

73. **Cum previi blocarea domeniilor legitime in content filtering?**  
    Folosesc allowlist, verificare manuala si testarea domeniului inainte de aplicarea politicii.

74. **Cum ai extinde aplicatia pentru mai multi utilizatori?**  
    As adauga conturi, roluri, baza de date, autentificare persistenta si audit log pentru actiunile fiecarui utilizator.

75. **Cum ai transforma proiectul intr-o platforma enterprise?**  
    As adauga agenti pe mai multe statii, server central, politici distribuite, raportare centralizata si integrare cu SIEM.

76. **Cum ai reduce riscul ca un fisier periculos sa fie acceptat ca sigur?**  
    As combina mai multe surse de detectie: semnaturi, YARA, euristici, sandbox, reputatie hash si analiza comportamentala.

77. **Cum tratezi un rezultat incert, cum ar fi statusul REVIEW?**  
    Il marchez pentru analiza manuala, nu il consider automat sigur si ofer detalii despre motivele suspiciunii.

78. **De ce este utila asocierea cu MITRE ATT&CK?**  
    Ajuta la explicarea comportamentului atacului, nu doar la afisarea unui rezultat simplu de tip infectat sau curat.

79. **Cum ai proteja comunicarea dintre frontend si backend intr-o versiune publica?**  
    As folosi HTTPS, autentificare mai stricta, token-uri securizate, rate limiting si validare riguroasa a inputului.

80. **Ce se intampla daca un serviciu extern de analiza nu raspunde?**  
    Aplicatia trebuie sa afiseze eroarea sau statusul indisponibil, dar scanarea locala poate continua independent.

81. **De ce este important logging-ul in securitate?**  
    Logurile permit investigarea incidentelor, urmarirea actiunilor si identificarea momentului in care a aparut o problema.

82. **Cum ai explica pe scurt diferenta dintre IOC si comportament suspect?**  
    Un IOC este un indicator concret, precum IP, domeniu sau hash, iar comportamentul suspect este o actiune sau combinatie de actiuni care pot indica un atac.

83. **De ce arhivele trebuie scanate diferit fata de fisierele simple?**  
    Arhivele pot contine mai multe fisiere ascunse in interior, deci trebuie desfacute si analizate pe fiecare intrare.

84. **Ce inseamna obfuscarea scripturilor?**  
    Obfuscarea inseamna ascunderea intentiei codului prin codare, string-uri greu de citit sau comenzi construite dinamic.

85. **De ce este important sa existe buton de eliminare sau dezactivare pentru proxy?**  
    Pentru ca utilizatorul trebuie sa poata reveni rapid la conexiunea normala daca politica de filtrare blocheaza ceva gresit.

86. **Cum ai explica proiectul in 30 de secunde?**  
    Argus este o platforma locala de securitate care reuneste monitorizarea sistemului, scanarea antivirus, firewall-ul, filtrarea web, threat intelligence si alertele live intr-o singura interfata web.

87. **Ce date ar trebui sa NU fie trimise catre servicii externe fara acord?**  
    Fisiere personale, documente confidentiale, chei, parole, date medicale, date financiare sau orice informatie sensibila.

88. **De ce exista optiune de public submission pentru Hybrid Analysis?**  
    Pentru ca unele servicii pot face analiza publica sau partajata, iar utilizatorul trebuie sa isi dea acordul explicit.

89. **Cum ai imbunatati performanta daca listele de domenii devin foarte mari?**  
    As folosi structuri de date eficiente, cache, indexare, incarcarea incrementala si verificari optimizate pe domenii.

90. **Care este concluzia proiectului?**  
    Proiectul demonstreaza cum pot fi integrate mai multe concepte de securitate intr-o platforma locala, interactiva si extensibila.

