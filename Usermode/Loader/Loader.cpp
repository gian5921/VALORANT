#include "Driver.hpp"
#include "Bridge.hpp"

int main ( /*int* argc, char** argv []*/ )
{
	SPOOF_FUNC;

	if ( !Initialise ( ) ) {
		std::cout << _XOR_ ( "[!] Initialisation Failed.\n" ) << std::flush;
		return FALSE;
	}

	ProcessID = GetProcessID ( _XOR_ ( L"VALORANT-Win64-Shipping.exe" ) );
	ImageBase = GetImageBase ( );

	SetGuardedRegion ( );

	std::jthread ( Cache ).detach ( );

	for ( ;; )
	{
		Bridge ( );
	};

	static_cast<void>( std::getchar ( ) );

	return NULL;
};