#pragma once
#include "Decryption.hpp"
#include "Offsets.hpp"
#include "SDK.hpp"

namespace EntitySDK
{
	auto GetEntityBone ( std::uintptr_t Mesh, std::int32_t Id ) -> FVector
	{
		std::uintptr_t BoneArray = Read<std::uintptr_t> ( Mesh + Offsets::BoneArray );
		if ( BoneArray == NULL )
			BoneArray = Read<std::uintptr_t> ( Mesh + Offsets::BoneArrayCache);

		FTransform Bone = Read<FTransform> ( BoneArray + ( Id * 0x30 ) );

		FTransform ComponentToWorld = Read<FTransform> ( Mesh + Offsets::ComponentToWorld );
		D3DMATRIX Matrix;

		Matrix = MatrixMultiplication ( Bone.ToMatrixWithScale ( ), ComponentToWorld.ToMatrixWithScale ( ) );

		return FVector ( Matrix._41, Matrix._42, Matrix._43 );
	};

	auto ProjectWorldToScreen ( FVector WorldLocation ) -> FVector
	{
		FVector Screenlocation = FVector ( 0, 0, 0 );

		auto ViewInfo = Read<FMinimalViewInfo> ( PlayerCameraManager + 0x1FE0 + 0x10 );

		CameraLocation = ViewInfo.Location;
		CameraRotation = ViewInfo.Rotation;

		D3DMATRIX TemporaryMatrix = Matrix ( CameraRotation, FVector ( 0, 0, 0 ) );

		FVector AxisX = FVector ( TemporaryMatrix.m [0][0], TemporaryMatrix.m [0][1], TemporaryMatrix.m [0][2] ),
			AxisY = FVector ( TemporaryMatrix.m [1][0], TemporaryMatrix.m [1][1], TemporaryMatrix.m [1][2] ),
			AxisZ = FVector ( TemporaryMatrix.m [2][0], TemporaryMatrix.m [2][1], TemporaryMatrix.m [2][2] );

		FVector Delta = WorldLocation - CameraLocation;
		FVector Transformed = FVector ( Delta.Dot ( AxisY ), Delta.Dot ( AxisZ ), Delta.Dot ( AxisX ) );

		if ( Transformed.z < 1.f ) Transformed.z = 1.f;

		FOVAngle = ViewInfo.FOV;

		float ScreenCenterX = Width / 2.0f;
		float ScreenCenterY = Height / 2.0f;

		Screenlocation.x = ScreenCenterX + Transformed.x * ( ScreenCenterX / tanf ( FOVAngle * (float) M_PI / 360.f ) ) / Transformed.z;
		Screenlocation.y = ScreenCenterY - Transformed.y * ( ScreenCenterX / tanf ( FOVAngle * (float) M_PI / 360.f ) ) / Transformed.z;

		return Screenlocation;
	}
};

std::uintptr_t DecryptWorld ( std::uintptr_t Pointer )
{
	const auto UWorldKey = Read<std::uint64_t> ( reinterpret_cast<std::uint64_t>( ImageBase ) + Offsets::UWorldKey );
	const auto UWorldState = Read<State> ( reinterpret_cast<std::uintptr_t>( ImageBase ) + Offsets::UWorldState );
	const auto UWorldPointer = DecryptUWorld ( UWorldKey, (std::uintptr_t*) &UWorldState );

	return Read< std::uint64_t> ( UWorldPointer );
};

std::vector<EntityList> RetrieveEntity ( std::uint64_t ActorArray, std::int32_t ActorCount )
{
	std::vector<EntityList> TemporaryEntity {};
	std::size_t Size = sizeof ( std::uintptr_t );

	for ( auto Iteration = 0; Iteration < ActorCount; Iteration++ )
	{
		auto Actor = Read<std::uintptr_t> ( ActorArray + ( Iteration * Size ) );

		if ( !Actor )
			continue;

		auto UniqueID = Read<std::uintptr_t> ( Actor + Offsets::UniqueID );

		if ( UniqueID != LocalUniqueID )
			continue;

		auto MeshComponent = Read<std::uintptr_t> ( Actor + Offsets::MeshComponent );

		if ( !MeshComponent )
			continue;

		auto RootComponent = Read<std::uintptr_t> ( Actor + Offsets::RootComponent );

		EntityList Enemy
		{
			Actor,
			MeshComponent,
			RootComponent
		};

		/*auto PlayerState = Read<std::uintptr_t> ( Actor + Offsets::PlayerState );
		auto TeamComponent = Read<std::uintptr_t> ( PlayerState + Offsets::TeamComponent );

		auto TeamId = Read<std::int32_t> ( TeamComponent + Offsets::TeamID );
		auto BoneCount = Read<std::int32_t> ( MeshComponent + Offsets::BoneCount );

		bool IsBot = BoneCount == 103;

		if ( TeamId == LocalTeamID && !IsBot )
		     continue;*/

#if _DEBUG_MODE
		std::printf ( _XOR_ ( "[+] Actor => 0x%p\n" ), Actor );
		std::printf ( _XOR_ ( "[+] MeshComponent => 0x%p\n" ), MeshComponent );
		std::printf ( _XOR_ ( "[+] RootComponent => 0x%p\n" ), RootComponent );
#endif

		TemporaryEntity.push_back ( Enemy );
	};

	EnemyCollection.clear ( );
	EnemyCollection = TemporaryEntity;

	return TemporaryEntity;
};

auto Cache ( ) -> void
{
	for ( ;; )
	{
		auto UWorld = DecryptWorld ( reinterpret_cast<std::uintptr_t>( ImageBase ) );

		auto GameInstance = Read<std::uintptr_t> ( UWorld + Offsets::GameInstance );
		auto PersistentLevel = Read<std::uintptr_t> ( UWorld + Offsets::PersistentLevel );
		auto LocalPlayerArray = Read<std::uintptr_t> ( GameInstance + Offsets::LocalPlayerArray );
		auto LocalPlayer = Read<std::uintptr_t> ( LocalPlayerArray );

		PlayerController = Read<std::uintptr_t> ( LocalPlayer + Offsets::PlayerController );
		PlayerCameraManager = Read<std::uintptr_t> ( PlayerController + Offsets::PlayerCameraManager );

		LocalPawn = Read<std::uintptr_t> ( PlayerController + Offsets::LocalPawn );

		auto ActorArray = Read<std::uintptr_t> ( PersistentLevel + Offsets::ActorArray );
		auto ActorCount = Read<std::int32_t> ( PersistentLevel + Offsets::ActorCount );

		if ( LocalPawn != 0 )
		{
			LocalUniqueID = Read<std::uintptr_t> ( LocalPawn + Offsets::UniqueID );
			PlayerState = Read<std::uintptr_t> ( LocalPawn + Offsets::PlayerState );
			RootComponent = Read<std::uintptr_t> ( LocalPawn + Offsets::RootComponent );
			LocalTeamID = Read<std::int32_t> ( Read<std::uintptr_t> ( PlayerState + Offsets::TeamComponent ) + Offsets::TeamID );

#if _DEBUG_MODE
			std::printf ( _XOR_ ( "[+] LocalUID => 0x%p\n" ), LocalUniqueID );
			std::printf ( _XOR_ ( "[+] PlayerState => 0x%p\n" ), PlayerState );
			std::printf ( _XOR_ ( "[+] RootComponent => 0x%p\n" ), RootComponent );
			std::printf ( _XOR_ ( "[+] TeamId => 0x%p\n" ), LocalTeamID );
#endif
		};

#if _DEBUG_MODE
		std::printf ( _XOR_ ( "[+] UWorld => 0x%p\n" ), UWorld );
		std::printf ( _XOR_ ( "[+] GameInstance => 0x%p\n" ), GameInstance );
		std::printf ( _XOR_ ( "[+] PersistentLevel => 0x%p\n" ), PersistentLevel );
		std::printf ( _XOR_ ( "[+] LocalPlayer => 0x%p\n" ), LocalPlayer );
		std::printf ( _XOR_ ( "[+] PlayerController => 0x%p\n" ), PlayerController );
		std::printf ( _XOR_ ( "[+] PlayerCameraManager => 0x%p\n" ), PlayerCameraManager );
		std::printf ( _XOR_ ( "[+] LocalPawn => 0x%p\n" ), LocalPawn );
#endif

		EnemyCollection = RetrieveEntity ( ActorArray, ActorCount );
	};
};

auto Bridge ( ) -> void
{
	for ( ;; )
	{
		std::vector<EntityList> LocalEnemyCollection = EnemyCollection;

		for ( auto Iteration = 0; Iteration < LocalEnemyCollection.size ( ); Iteration++ )
		{
			EntityList Enemy = LocalEnemyCollection [Iteration];

			auto Dormant = Read<bool> ( Enemy.Actor + Offsets::Dormant );
			auto DamageHandler = Read<std::uintptr_t> ( Enemy.Actor + Offsets::DamageHandler );
			auto Health = Read<float> ( DamageHandler + Offsets::Health );

			auto PlayerState = Read<std::uintptr_t> ( Enemy.Actor + Offsets::PlayerState );
			auto TeamComponent = Read<std::uintptr_t> ( PlayerState + Offsets::TeamComponent );
			auto TeamId = Read<std::int32_t> ( TeamComponent + Offsets::TeamID );

			if ( Enemy.Actor == LocalPawn || !Enemy.MeshComponent || Health <= 0 || !Dormant )
				continue;

			if (Read<std::uint64_t>( std::uint64_t( Enemy.MeshComponent ) + Offsets::OutlineMode ) != 1)
				Write<std::uint64_t>( std::uint64_t( Enemy.MeshComponent ) + Offsets::OutlineMode, 1 );

			TArray<std::uint64_t> AttachChildren = Read<TArray<std::uint64_t>> ( std::uint64_t ( Enemy.MeshComponent ) + Offsets::AttachChildren );
			for ( auto Iteration = 0; Iteration < AttachChildren.Length ( ); Iteration++ )
			{
				if ( std::uint64_t CurrentMesh = AttachChildren.GetById ( Iteration ) )
				{
					if ( !CurrentMesh )
						continue;

					if ( Read<std::uint64_t> ( std::uint64_t ( CurrentMesh ) + Offsets::OutlineMode ) == 3 )
						Write<std::uint64_t> ( std::uint64_t ( CurrentMesh ) + Offsets::OutlineMode, 1 );

					// Blue Neon \\
					
					Write<FLinearColor> ( reinterpret_cast<std::uintptr_t>( ImageBase ) + Offsets::OutlineAlly, { 5.093f, 5.019f, 20.066f, 4.55f } );
					Write<FLinearColor> ( reinterpret_cast<std::uintptr_t>( ImageBase ) + Offsets::OutlineEnemy, { 5.093f, 5.019f, 20.066f, 4.55f } );

					// Red \\

					/*Write<FLinearColor> ( reinterpret_cast<std::uintptr_t>( ImageBase ) + Offsets::OutlineAlly, { 1.000f, 0.001f, 0.001f, 50.55f } );
					Write<FLinearColor> ( reinterpret_cast<std::uintptr_t>( ImageBase ) + Offsets::OutlineEnemy, { 1.000f, 0.001f, 0.001f, 50.55f } );*/
				};
			};

			Write<float> ( Enemy.Actor + Offsets::FresnelIntensity, 100.f );
		};
	};
};