#pragma once

namespace Offsets
{
	constexpr std::uintptr_t UWorldKey = 0x9282978;
	constexpr std::uintptr_t UWorldState = 0x9282940;

	constexpr std::uintptr_t UniqueID = 0x38;

	constexpr std::uintptr_t FresnelIntensity = 0x6B8;

	constexpr std::uintptr_t GameInstance = 0x1A0;

	constexpr std::uintptr_t LocalPawn = 0x460;
	constexpr std::uintptr_t LocalPlayerArray = 0x40;

	constexpr std::uintptr_t PersistentLevel = 0x38;
	constexpr std::uintptr_t PlayerState = 0x3F0;
	constexpr std::uintptr_t PlayerController = 0x38;
	constexpr std::uintptr_t PlayerCameraManager = 0x478;

	constexpr std::uintptr_t TeamComponent = 0x628;
	constexpr std::uintptr_t TeamID = 0xF8;

	constexpr std::uintptr_t BoneArray = 0x5C0;
	constexpr std::uintptr_t BoneArrayCache = BoneArray + 0x10;
	constexpr std::uintptr_t BoneCount = 0x5C8;

	constexpr std::uintptr_t ActorArray = 0xA0;
	constexpr std::uintptr_t ActorCount = 0xB8;

	constexpr std::uintptr_t AttachChildren = 0x110;

	constexpr std::uintptr_t ComponentToWorld = 0x250;

	constexpr std::uintptr_t MeshComponent = 0x430;
	constexpr std::uintptr_t RootComponent = 0x230;

	constexpr std::uintptr_t DamageHandler = 0x9A8;
	constexpr std::uintptr_t Dormant = 0x100;
	constexpr std::uintptr_t Health = 0x1B0;

	constexpr std::uintptr_t OutlineMode = 0x330;

	constexpr std::uintptr_t OutlineAlly = 0x919D470;
	constexpr std::uintptr_t OutlineEnemy = 0x919DB00;
}