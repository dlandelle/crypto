/*********************************************************************
                                 CRYPTO

Programme de cryptage indéterminable, sans backdoor, incrackable.
Ce programme ne repose pas sur les principes habituel du cryptage.

Voici les principes utilisés :
-pas d'algorithme, pas de backdoors
-application récursive de LUT
-profondeur de récursivité indéterminée (dépendant des données)
-traitement par paquets de taille indéterminée
-inversion de l'ordre des octets par paquet
-codage successif genre excursion de fréquence (N+1 dépend de N)
-critère d'arrêt / platitude histogramme (entropie maximale)
Corrolaire :
-conservation de la volumétrie

Amélioration possible :
* ajout de bruit à certains endroits (pseudo-aléatoire)
* utilisation de buit de type signal (texte libre)

Sans la clef il est impossible de craquer le message par "brute force"
même avec le code source, car le nombre de degré de liberté n'est
pas connu a priori (il dépend des données). De plus, la combinatoire
LUT à chaque étape est de l'ordre de 256! (factorielle 256)

Ce type de cryptage est fragile aux pertes, pas adapté télécom raw.
Mais ok sur un filesystem ou un protocole sans pertes.

This program is performing a size invariant negentropic obfuscation
it tries to hide any structure and produces a near to flat histogram
no compression algorithm should perform well on the result (this is
considered as an antropy tester).

usage (command line) :
crypto entree.txt sortie.txt -k "superbe clef de protection"

Libre de droit.
David LANDELLE, Noël 2013.
*********************************************************************/
//////////////////////////////////////////////////////////////////////
/********************************************************************
                          notes techniques

L'implémentation est entachée de son origine win32.
Le codage est effectué par paquets ou segments de taille différentes.
Et chaque segment est codé avec un nombre d'itération différent.
Les octets sont renversés dans le segment
(après lecture pour le décryptage, avant écriture pour le cryptage)

Janvier 2012 : histogramme pas totalement plat, affine, régulier
Juillet 2012 : amélioration affichage histogramme
        2013 : adaptatif / taille fichier
        2014 : portage Linux
        2016 : usage sous debian 6 7 8 9 dont kali

current environment:
gcc -dumpversion           4.7
gcc -dumpmachine           i486-linux-gnu
uname -a                   Linux serveur 3.18.0-kali3-686-pae
#1 SMP Debian 3.18.6-1~kali2 (2015-03-02) i686 GNU/Linux

TODO
Back on WIN32 for interop
Static link to get rid of dynamic libraries
Il reste un octet le plus probable, pourquoi ?
Padding pseudo-random pour histogramme plat.
Intéressant que si padding saupoudré, et pas dropé à la fin.
*********************************************************************/

// GENERAL GNU INCLUDES

#define _XOPEN_SOURCE 500

#include <features.h>
#include <stdio.h>
#include <unistd.h>

// to avoid error PATH_MAX undeclared here (not in a function) :
#include <linux/limits.h>

#include <string.h>
#include <stdlib.h> 

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <errno.h>

// SPECIFIC BLOODY WIN32 HERITAGE
#include "windows_types.h"

/* Default internal seed, I like this one */
char *TheSeed="This program cannot be run in DOS mode";

// paramètre adaptatif de taille de paquet
// ce nombre sert à multiplier l'indice courant dans la LUT
// pour obtenir la taille du n ieme buffer utilisé
// 1000 va très bien pour un fichier à partir du Mo
// 47 too big for histogram break of small messages
// 1 n'est pas génial pour des fichiers de 40Ko
DWORD CRYPTO_ROOT =0;
// la valeur est fixée dès le départ selon la taille du fichier
// elle conditionne également les deux paramètres suivants

// buffer alloué, taille maximale de travail
// must be a DWORD size (multiple of 4)
#define CRYPTO_BUFFER_SIZE (4L*256*CRYPTO_ROOT)
// taille de travail du bloc courant
// le paramètre b est un octet 0..255
#define CRYPTO_PACKET_SIZE(b) (4L*(b)*CRYPTO_ROOT)

char input_filename[PATH_MAX];
char output_filename[PATH_MAX];
enum { encrypter, decrypter, analyser, generer, noop } crypt_mode;

// Look Up Table principale pour la translation d'octets
// les valeurs sont bidons, et seront remplacées par les bonnes
int LutI[]/*[256];*/
={	  9,246,225,  7,185, 10, 13,  3, 26,  0,  5,122,253, 6,  15, 14,147, 19,196, 17,
				 82, 81, 80, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
				 11,121,220,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,119,139,
				103,104,101,163,164,165,166,167,168,249,170,171,172,252,174,175,176,177,178,215,
				 43, 41, 42, 40, 44, 45, 46, 47, 48,200, 50, 51, 52, 53, 54, 55, 56, 57, 58,211,
				 49,201,202,243,204,205,206,254,208,209,210, 59,212,213,214,179,216,217,218,219,
				140,141,142,143,195,145,146, 16,148,149, 78,151,152,153,154,155,156,157,158,159,
				100,105,102,160,161,162,106,107,108,109, 30, 31, 32, 33, 34,115,116,117,118,138,
				 21, 20, 24, 23, 22, 25,  8, 27, 28, 29,110,111,112,113,114, 35, 36, 37, 38, 77,
				 61, 60, 62, 68, 64, 65, 66, 67, 63, 69, 70, 71, 72,236, 74, 75, 76, 39,150, 79,
				222,221,120,223,224,  2,226,227,228,229,230,231,255,233,234,235, 73,237,238,239,
				180,241,182,183,184,  4,186,187,188,189,190,191,192,193,194,144, 18,197,198,199,
				242,181,240,203,245,244,  1,250,251,169,247,248,173,207, 12,232};

// initialization : hard work, cette LUT est testée en mode DEBUG pour être bijective
int LutC[]/*[256];*/
={	  9,246,225,  7,185, 10, 13,  3, 26,  0,  5,122,253, 6,  15, 14,147, 19,196, 17,
				 43, 41, 42, 40, 44, 45, 46, 47, 48,200, 50, 51, 52, 53, 54, 55, 56, 57, 58,211,
				140,141,142,143,195,145,146, 16,148,149, 78,151,152,153,154,155,156,157,158,159,
				100,105,102,160,161,162,106,107,108,109, 30, 31, 32, 33, 34,115,116,117,118,138,
				 21, 20, 24, 23, 22, 25,  8, 27, 28, 29,110,111,112,113,114, 35, 36, 37, 38, 77,
				 61, 60, 62, 68, 64, 65, 66, 67, 63, 69, 70, 71, 72,236, 74, 75, 76, 39,150, 79,
				222,221,120,223,224,  2,226,227,228,229,230,231,255,233,234,235, 73,237,238,239,
				 82, 81, 80, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
				 11,121,220,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,119,139,
				103,104,101,163,164,165,166,167,168,249,170,171,172,252,174,175,176,177,178,215,
				180,241,182,183,184,  4,186,187,188,189,190,191,192,193,194,144, 18,197,198,199,
				 49,201,202,243,204,205,206,254,208,209,210, 59,212,213,214,179,216,217,218,219,
				242,181,240,203,245,244,  1,250,251,169,247,248,173,207, 12,232};

void crypto_usage(void)
{
	printf("Usage ! crypto LVS build gcc\n");
	printf("   crypto <input> <output> [-k \"jolie clef\"]     => encrypt\n");
	printf("   crypto <input> <output> -d [-k \"jolie clef\"]  => decrypt\n");
	printf("   crypto <input> <output> -nop                  => null transform\n");
	printf("   crypto <input>                                => analyze\n");
	printf("   crypto -g                                     => generate Lut\n");
	printf("   crypto -h                                     => more help\n");
	exit(-1);
}

void BuildLastError(char *msg) // 80 char max
{
	strcpy(msg, strerror(errno));
} 

/* Appliquer la LUT "lut", sur le "buffer" en lieu et place (écrasement)
 * Remplacement de "size" octets exactement
 * side effect : le pointeur "lut" peut contenir la LUT directe "LutC"
 * ou la LUT inverse "LutI"
 * différentes variantes sont proposée, et une macro finale définit
 * la variante choisie (Simple, Shift de brouillage, Complexe)
 * en commentaire inline le ratio d'étalement d'histogramme 0.5 is OK
 * NOTE ON GNU COMPILER
 * a warning is issued on *buffer = lut[ *buffer++ ];
 * which does not give the same result on MSVC
 * (where pointer is incremented after the end of line ;) */
void look_up_table_simple(BYTE *buffer, DWORD size, int *lut) // 0.06 min/max
{
	if(lut==NULL) return;
	DWORD i;
	for(i=0; i<size; i++) // each BYTE
	{
		*buffer = lut[ *buffer ];
		buffer++;
	}
}
void look_up_table_shift(BYTE *buffer, DWORD size, int *ptrLut) // 0.53
{
	if(ptrLut==NULL) return;
	DWORD i;
	if(ptrLut==LutC) { /* encodage */
		for(i=0; i<size; i++) {
			/* a chaque octet on ajoute i via le "i+"
			 * et on tronque sur 1 BYTE pour rester dans
			 * l'espace d'adressage de la LUT */
 			*buffer = ptrLut[ (i + *buffer) & 0xFF ];
			buffer++;
		}
	} else if(ptrLut==LutI) { /* décodage */
		for(i=0; i<size; i++) {
			/* inversement, on prend l'antécédent de l'octet
			 * dans la LUT inverse, et on soustrait i */
			*buffer = (BYTE)( ptrLut[ *buffer ] + 256 - i);
			buffer++;
		}
	} else printf("4-internal error\n");
}
void look_up_table_full(BYTE *buffer, DWORD size, int *ptrLut)
{
	/* too bad, so far */
}
#define look_up_table look_up_table_shift

void hm_parameters(int argc, char **argv)
{
	if(argc<2) crypto_usage();
	crypt_mode = analyser; // default if argc==2
	if ( (strncmp(argv[1],"--h",3) == 0) || (strncmp(argv[1],"-h",2) == 0) ) // --h* -h* -help
	{
		printf("crypto LVS V1.0 is generating high encryption files with a \"user key\"\n");
		printf("   the \"user key\" must be sent to the contact by another way\n");
		printf("   or be part of shared intimate knowledge\n");
		printf("good naming practice :\n");
		printf("   message.txt  the original message\n");
		printf("   messageC.txt the encrypted message (may be sent/uploaded)\n");
		printf("   messageD.txt the decrypted message\n");
		printf("   .txt extension is practical for quick opening\n");
		printf("examples (xterm command line):\n");
		printf("./crypto readme.txt readmeC.txt -k \"super clef\"\n");
		printf("./crypto readmeC.txt readmeD.txt -d -k \"super clef\"\n");
		printf("****************************************************************\n");
		crypto_usage(); // exit !
	}
	
	if (strncmp(argv[1],"-g",2) == 0)
	{
		printf("generation of pseudo-random LUT in C format (cut&paste in code)\n");
		DWORD nimportnawak=GetTickCount();
		printf("RAND_MAX = %d\n", RAND_MAX );
		for (int i=0; i<256; i++) printf("%d ", (BYTE) rand_r(&nimportnawak));
		printf("done.\n");
		exit(-1);

	}
	
	if(realpath(argv[1], input_filename)==NULL)
	{
		printf("Cannot build full path for input file %s\n", argv[1]);
		crypto_usage();
	}
	if(argc==2) goto analyse_seule; // if only one parameter : mode analyse
	strcpy(output_filename, argv[2]);
	crypt_mode = encrypter; // default
	int i;
	for (i = 3 ; i < argc ; i++) // if third parameter is present
	{
		if ( strncmp(argv[i],"-k",2) == 0)
		{
			TheSeed=argv[i+1];
			printf("Key \"%s\" ", TheSeed);
		}
		if ( strncmp(argv[i],"-d",2) == 0)
		{
			crypt_mode = decrypter;
		}
		if ( strncmp(argv[i],"-nop",2) == 0)
		{
			crypt_mode = noop;
		}
	}
analyse_seule:
	switch(crypt_mode) {
		case encrypter: printf("Crypt "); break;
		case decrypter: printf("Decrypt "); break;
		case analyser:  printf("Analyze "); break;
		case generer:   printf("Generate "); break;
		case noop:      printf("Noop "); break;
	}
}

// clef arbitrairement longue fabriquée à partir de la clef utilisateur
BYTE SeedElements[256];

// Histogramme pour l'analyse statistique (espaces, lettres)
typedef struct 
{
   BYTE index;
   DWORD num;
}tHistogrammeElement;


tHistogrammeElement Histogramme[256];

// pour l'obfuscation de séquences ordonnées
// inversion d'un bloc d'octet pair
void reverse_buffer(BYTE *buffer, DWORD size)
{
	DWORD i;
	BYTE swap;
	int sym;
	return; // noop version
	/* il faut un nombre pair, last packet may be odd */
	if((size%2)>0) size--;
	for(i=0; i<(size/2); i++) // each BYTE
	{
		sym=size-1-i; // par exemple 99 pour un buffer de 100
		// 0 <-> 99     1 <-> 98    49 <-> 50
		swap = *(buffer+i);
		*(buffer+i) = *(buffer+sym);
		*(buffer+sym) = swap;
		//printf("%d<->%d ", i, sym);
	}
}

int compare_histo( const void *arg1, const void *arg2 ) // for qsort
{
	tHistogrammeElement *h1 = (tHistogrammeElement*) arg1;
	tHistogrammeElement *h2 = (tHistogrammeElement*) arg2;
	if ((h1->num) > (h2->num)) return -1 ;
	if ((h1->num) < (h2->num)) return 1 ;
	return 0 ;
}

// centré sur 128
// appelé jusqu'à remplir la LUT
/* à chaque appel, l'index pourri se déplace dans le tableau pseudo-random   */
/* l'addition de la valeur dans ce non tout nulle garantit le balayage dense */
/* dans l'ensemble 0..FF et l'obtention déterministe de toutes les valeurs   */
/* par le modulo (troncature à BYTE)                                         */
BYTE pseudo_random_byte()
{
	static BYTE rotten_index=0;
	static BYTE rotten_value=0;
	rotten_value+=SeedElements[rotten_index]; /* overflow, maybe */
	rotten_index+=3;
	return rotten_value;
}

/*********************************************************************************************/
/* fabriquer une LUT bijective de cryptage LutC, faite de 256 valeurs et sa LUT inverse LutI */
/* en paramètre une clef utilisateur de moins de 128 caractères qui sert à l'initialiser     */
/*********************************************************************************************/
void build_luts_from_seed( char *theSeed )
{
	int userSeedSize=(int)strlen(theSeed);
	if(userSeedSize>=128) {
		printf("User key too long : 128 character max\n");
		crypto_usage();
	}
	/* fabriquer un tableau pseudo-random SeedElements */
	int seedSize=2*userSeedSize; // TheSeed="lagraine";
	/* Ventiler la clé sur les octets pairs */
	for(int i=0; i<userSeedSize; i++) SeedElements[i*2] = (BYTE)(787L*theSeed[i]*theSeed[i]);
	/* Ventiler la clé à l'envers sur les octets impairs */
	for(int i=0; i<userSeedSize; i++) SeedElements[i*2+1] = (BYTE)(666L*theSeed[userSeedSize-i-1]*theSeed[userSeedSize-i-1]);
	/* tartiner jusqu'à la fin de la LUT */
	for(int i=seedSize; i<256; i++) SeedElements[i] = (BYTE)(SeedElements[i-seedSize]*SeedElements[i-seedSize]); // repeat until 256 char

	// BUILD LutC direct LUT
	for(int courant=0; courant<256; courant++) {
		BYTE octet;
		int verif;
		do {
			octet=pseudo_random_byte(); /* toute valeur finit par arriver */
			/* une manière efficace de faire une boucle 0..courant-1 */
			/* pour vérifier que octet pressentit est nouveau dans la liste */
			/* (pas en doublon avec une valeur antérieure dans la LUT LutC) */
			/* et qu'il n'est pas l'image de lui-même dans la LUT LutC      */
			verif=0;
			while( verif<courant && LutC[verif]!=octet && octet!=courant ) verif++;
		} while ( verif<courant );
		/* si on est sorti, cela signifie verif>=courant, most probably vérif=courant */
		/* donc LutC[0..courant-1]!=octet && octet!=courant) */
		LutC[courant]=octet;
		/* ainsi on remplit la LUT avec f(b)!=b, aucun octet n'est conservé                */
		/* et chaque nouvelle valeur au rang courant n'est pas déjà existante 0..courant-1 */
		/* le succès de la sortie de la boucle est assurée par la densité de la fonction   */
		/* pseudo_random_byte() et garantit le caractère bijectif de la LUT LutC           */
	}

	// BUILD LutI inverse LUT
	for(int i=0; i<256; i++)
		for(int j=0; j<256; j++)
			if(i==LutC[j]) LutI[i]=j;

	// Bad Karma ?
	for(int cc=0; cc<256; cc++)
		if(LutC[cc]==cc)
		{
			printf("3-Internal Error [%d]", cc);
		}
}

//////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	int hFichierIn; 
	int hFichierOut; 
	DWORD nbRead, nbWritten; 
	SQWORD TailleFichier64=0; // BYTE unit
	SQWORD TailleLue64=0; // BYTE unit
	int *ptrLut;

	DWORD *GlobalBuffer=NULL;
	BYTE  *ByteGlobalBuffer = NULL;

	hm_parameters(argc, argv); /* side effect on TheSeed & printf */
	build_luts_from_seed( TheSeed );

	if(access(input_filename, 0)!=0)
	{
		printf("Cannot _access() Input File : <%s>\n", input_filename);
		crypto_usage();
	}
	else printf("File %s ", argv[1]);
	struct stat sb;
	if (stat(input_filename, &sb) == -1) {
		printf("Cannot stat Input File : <%s>\n", input_filename);
		exit(-2);
	}
	TailleFichier64=sb.st_size;
	printf("%lld octets ", TailleFichier64);

	DWORD millisecondPT0=GetTickCount();

	hFichierIn=open(input_filename, O_EXCL|O_RDONLY);
	if ( hFichierIn == INVALID_HANDLE_VALUE ) {
		char msg[256]; BuildLastError(msg);
		printf("Error opening input file %s\n%s\n", input_filename, msg);
		exit(-3);
	}

	// paramètre adaptatif
	if(TailleFichier64<40000L) CRYPTO_ROOT=1;
	else if (TailleFichier64<1000000L) CRYPTO_ROOT=47;
	else CRYPTO_ROOT=1000;

	GlobalBuffer=(DWORD *) malloc( CRYPTO_BUFFER_SIZE );
	if (GlobalBuffer==NULL) {
		char msg[256]; BuildLastError(msg);
		printf("Error allocating memory : %s\n", msg);
		exit(-4);
	}

	ByteGlobalBuffer = (BYTE *)GlobalBuffer;
	int lastPourcent=0;
	int pourcent=0;

	/* Première passe d'analyse statistique */
	TailleLue64=0;
	for(int j=0; j<=0xFF; j++) { Histogramme[j].num=0; Histogramme[j].index=(BYTE)j; }
	do
	{
		nbRead=0;
		/* lecture par bloc de taille fixe (et max)*/
		nbRead = read( hFichierIn, ByteGlobalBuffer, CRYPTO_BUFFER_SIZE );
		if (nbRead==-1) {
			char msg[256]; BuildLastError(msg);
			printf("Error reading file : %s\n", msg);
			goto fin;
		}
		if(nbRead==0) break; // no more data, sortie normale
		TailleLue64+=nbRead;
		if(TailleFichier64>100) pourcent = (int)(TailleLue64/(TailleFichier64/100));
		else pourcent=100;
		if(pourcent>100) pourcent=100;
		if(crypt_mode==analyser) // XXX pas la peine
		{
			pourcent/=10;
			if( pourcent!=lastPourcent ) { printf("%d0%% ", pourcent); lastPourcent=pourcent; }
		}
		for(DWORD j=0; j<nbRead; j++)
			Histogramme[ByteGlobalBuffer[j]].num++;
	} while(1);
	if(crypt_mode==analyser) printf("done.\n"); // sortie normale
	if (TailleLue64 != TailleFichier64) {
		printf("Erreur lecture (analyse) : TailleLue64 = %lld TailleFichier64 = %lld\n", TailleLue64, TailleFichier64);
		goto fin;
	}
	int dernier=255;
	if(crypt_mode==analyser) {
		printf("rank     nb ddd=xx=c\n");
		qsort(Histogramme, 256, sizeof(tHistogrammeElement), compare_histo);
		for(DWORD j=0; j<256; j++)
			if(Histogramme[j].num>0) {
				dernier=j;
				BYTE octet=Histogramme[j].index;
				if(octet==10 || octet==13) octet=32; // replace CR-LF by blank
				printf("%03d %7d,%03d=%02x=%c\n", j, Histogramme[j].num, octet, octet, octet);
			}
	//for(DWORD j=0; j<256; j++) printf("%03d = %02x : %d\n", j, j, Histogramme[j]);
	float ratio=((float)Histogramme[dernier].num)/Histogramme[0].num;
	printf("max/min = %f < entropie < 1.0 (flat histogram)\n", ratio);
	}

	if(crypt_mode==analyser) goto fin;

	/* Deuxième passe de traitement = encrypter, decrypter, noop */

	lseek(hFichierIn, 0, SEEK_SET); // rewind
	TailleLue64=0;
	hFichierOut = open( output_filename, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU );
	if ( hFichierOut == INVALID_HANDLE_VALUE ) {
		printf("Error opening output file %s\n", output_filename);
		goto fin;
	}

	lastPourcent=pourcent=0;
	bool premiere=true;
	int segment=0; /* afin de gérer l'excursion sur la taille du bloc de traitement */
	do
	{
		nbRead=0;
		/* lecture par bloc de taille variable pseudo random 1..256 */
		nbRead = read( hFichierIn, ByteGlobalBuffer, CRYPTO_PACKET_SIZE(1+LutI[segment]) );
		if ( nbRead==-1 ) {
			char msg[256]; BuildLastError(msg);
			printf("Error reading file : %s\n", msg);
			goto fin;
		}
		if(nbRead==0) break; // no more data
		TailleLue64+=nbRead;
		if(TailleFichier64>100) pourcent = (int)(TailleLue64/(TailleFichier64/100)); else pourcent=100;
		if(TailleFichier64>100000) // big file > 1 second
			{
			if(premiere) { premiere=false; printf("Please wait...\n"); }
			if( (pourcent%10==0) && pourcent!=lastPourcent )
				{
				DWORD millisecondPT1=GetTickCount();
				printf("%d%% in %d ms\n", pourcent, (int)millisecondPT1-(int)millisecondPT0);
				lastPourcent=pourcent;
				}
			}

		/* reverse_buffer() is called BEFORE decrypter, and AFTER encrypter */
		switch(crypt_mode) {
			case encrypter: ptrLut=LutC; break;
			case decrypter: ptrLut=LutI; reverse_buffer(ByteGlobalBuffer, nbRead); break;
			case noop:      ptrLut=NULL; break;
			case generer:   ptrLut=NULL; break;
			default:        ptrLut=NULL; break; // avoid warning on switch ;-)
		}
		/* LutI is used for the pseudo random buffer size : same for encrypter and decrypter */
		for(int j=0; j<=LutI[segment]; j++) look_up_table(ByteGlobalBuffer, nbRead, ptrLut);

		if(crypt_mode==encrypter) reverse_buffer(ByteGlobalBuffer, nbRead);
		
		nbWritten=write(hFichierOut, ByteGlobalBuffer , nbRead);
		if ( nbWritten==-1 ) {
			char msg[256]; BuildLastError(msg);
			printf("Error writing file : %s\n", msg);
			goto fin;
		}
		segment++;
		segment=segment&0xFF; // segment = 0 1 2 .. 255 0 1 ...
	} while(1);
	DWORD millisecondPT1=GetTickCount();
	printf("done in %d ms (%d KB/s).\n", (int)millisecondPT1-(int)millisecondPT0, (int)(TailleFichier64/(1+(int)millisecondPT1-(int)millisecondPT0)));
	if (TailleLue64 != TailleFichier64) {
		printf("Erreur lecture : TailleLue64 = %lld TailleFichier64 = %lld\n", TailleLue64, TailleFichier64);
		goto fin;
	}
	fin:

	//printf("%lld octets ", TailleFichier64);

	close(hFichierOut); hFichierOut=INVALID_HANDLE_VALUE;
	close(hFichierIn); hFichierIn=INVALID_HANDLE_VALUE;
	free( GlobalBuffer );
	exit(0);
}
