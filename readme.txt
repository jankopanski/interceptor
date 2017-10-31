Rozwiązanie w postaci pliku intercept.c skałada się z

funkcji: 
intercept_function
unintercept_function 
intercept_handler
lookup_handler 
get_dynamic 
elf_lookup 
gnu_lookup 
elf_hash 
gnu_hash
get_function_address 
match_symbol_name

struktury: intercept_data


Struktura intercept_data służy do przekazywania parametrów przez
funkcję dl_iterate_phdr.

Funkcje intercept_function i unintercept_function odwołują się
poprzez dl_iterate_phdr do intercept_handler i lookup_handler.
W pierwszym odwołaniu do intercept_function wskaźnik na funkcję
dl_iterate_phdr zostaje zapamiętany wewnątrz statycznej zmiennej
globalnej dl_iter_global_ptr oraz statycznej zmiennej lokalnej dl_iter_ptr
aby zapobiec sytuacji, w której użytkownik interceptuje funkcję
dl_iterate_phdr.

Funkcja lookup_handler służy do znalezienia prawdziwego adresu funkcji
o nazwie podanej w polu name struktury data.  lookup_handler zaczyna od
przejrzenia segmentu DYNAMIC i znalezienia adresów sekcji HASH, GNU_HASH,
STRTAB, SYMTAB, STRSZ, PLTGOT. W zależności o tego czy pliku EFL jest
obecna tablica haszująca symboli sysv czy gnu wykonywana jest funkcja
elf_lookup lub gnu_lookup, która zwróci adres do funkcji lub NULL w
przypadku nieznalezienia symbolu dla danej nazwy.

Funkcje elf_hash i gnu_hash służą do wyliczania haszy dla nazwy
symbolu.

elf_lookup oraz gnu_lookup chodzą po odpowiednich dla nich
tablicach haszujących i szukają w nich indeksu do tablicy symboli,
pod którym znajduje się symbol o nazwie symbol_name (name z
intercept_function). Nazwy symboli porównywane są za pomocą funkcji
match_symbol_name. Jeżeli znaleziony został adres o odpowiedniej nazwie
to wywoływana jest funkcja get_function_address, która zwraca adres
do funkcji w bibliotece współdzielonej.

Jeżeli typ symbolu to STT_GNU_IFUNC, czyli szukana funkcja jest indirect
function to wewnątrz funkcji get_function_address wywoływany jest
resolver dla szukanej funkcji, który zwraca jej prawdziwy adres.

Funkcja match_symbol_name sprawdza czy w tablicy symboli strtab dla
indeksu strtab_index znajduje się nazwa symbol_name, zwracając true
w takim przypadku.

Jeżeli adres funkcji uzyskany z wywołania lookup_handler nie był równy
ELFNULL (O) to wywoływana jest funkcja intercept_handler, której celem
jest podmiana adresu na odpowiedniej pozycji w tablicy GOT. Podobnie jak
lookup_handler zaczyna ona od iteracji po segmencie DYNAMIC, wyszukuje
sekcji PLTGOT, STRTAB, SYMTAB, STRSZ i JMPREL. STRTAB i SYMTAB posłużą
do porównywania nazw symboli. Dzięki dostępowi do sekcji JMPREL można
wyszukiwac relokacji  typu R_X86_64_JUMP_SLOT. Offset z odpowiedniego
wpisu do tablicy JMPREL dodany do adresu początku biblioteki
daje adres do odpowiedniego slotu w tablicy GOT, w który należy
podmienić znajdujący się tam adres na adres nowej funkcji. Funkcja
intercept_handler podmieni wszystkie takie wystąpienia.

Funkcja get_dynamic zwraca adres do segmentu DYNAMIC, gdy jest wywoływana
z funckji lookup_handler i intercept_handler.

Poniżej zamieszczam graf wywołań funkcji (wygenerowany przy pomocy
programu cflow):

    1 +-elf_hash: unsigned long (const unsigned char *name), <interceptor.c 40>
    2 +-elf_lookup: Elf64_Addr (const Elf32_Word *hashtab, const Elf64_Sym *symtab, const char *strtab, const char *symbol_name, Elf64_Addr libaddr), <interceptor.c 53>
    3   +-elf_hash: 1
    4   +-match_symbol_name: bool (const char *strtab, unsigned long strtab_index, const char *symbol_name), <interceptor.c 17>
    5   \-get_function_address: Elf64_Addr (const Elf64_Sym *symbol, Elf64_Addr libaddr), <interceptor.c 28>
    6     \-ELF64_ST_TYPE: <>
    7 +-get_dynamic: Elf64_Dyn * (const struct dl_phdr_info *info), <interceptor.c 106>
    8 +-get_function_address: 5
    9 +-gnu_hash: unsigned (const unsigned char *s), <interceptor.c 76>
   10 +-gnu_lookup: Elf64_Addr (const Elf32_Word *gnuhashtab, const Elf64_Sym *symtab, const char *strtab, const char *symbol_name, Elf64_Addr libaddr), <interceptor.c 84>
   11   +-gnu_hash: 9
   12   +-match_symbol_name: 4
   13   \-get_function_address: 5
   14 +-intercept_function: void * (const char *name, void *new_func), <interceptor.c 207>
   15   +-lookup_handler: int (struct dl_phdr_info info, size_t size, void *data), <interceptor.c 117>
   16   | +-get_dynamic: 7
   17   | +-elf_lookup: 2
   18   | \-gnu_lookup: 10
   19   \-intercept_handler: int (struct dl_phdr_info info, size_t size, void *data), <interceptor.c 162>
   20     +-get_dynamic: 7
   21     +-ELF64_R_TYPE: <>
   22     +-ELF64_R_SYM: <>
   23     \-match_symbol_name: 4
   24 +-match_symbol_name: 4
   25 +-unintercept_function: void (const char *name), <interceptor.c 221>
   26   +-lookup_handler: 15
   27   \-intercept_handler: 19

