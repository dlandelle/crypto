//rustines

#define NULL ((void *)0)

// Unsigned base types.
typedef unsigned char		BYTE;		// 8-bit  unsigned.
typedef unsigned short		_WORD;		// 16-bit unsigned.
typedef unsigned int		DWORD;		// 32-bit unsigned.
typedef unsigned long long	QWORD;		// 64-bit unsigned.
 
// Signed base types.
typedef	signed char			SBYTE;		// 8-bit  signed.
typedef signed short		SWORD;		// 16-bit signed.
typedef signed int  		INT;		// 32-bit signed.
typedef signed long long	SQWORD;		// 64-bit signed.
 
// Character types.
typedef char			    ANSICHAR;	// An ANSI character.
typedef unsigned short      UNICHAR;	// A unicode character.
typedef unsigned char		ANSICHARU;	// An ANSI character.
typedef unsigned short      UNICHARU;	// A unicode character.
 
// Other base types.
typedef signed int			UBOOL;		// Boolean 0 (false) or 1 (true).
typedef float				FLOAT;		// 32-bit IEEE floating point.
typedef double				DOUBLE;		// 64-bit IEEE double.
typedef unsigned int        SIZE_T;     // Corresponds to C SIZE_T.
 
// Bitfield type.
typedef unsigned int		BITFIELD;	// For bitfields.
 
//typedef unsigned int size_t;

typedef BYTE bool;
#define true 1
#define false 0

void GetVolumeInformation(char *s1, char *s2, INT i1, DWORD *i2, DWORD *i3, DWORD *i4, char *s3, INT i5);
unsigned long GetTickCount();

#define INVALID_HANDLE_VALUE (-1)

