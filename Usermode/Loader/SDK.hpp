#pragma once

std::uintptr_t PlayerState, PlayerController, PlayerCameraManager, LocalPawn, LocalUniqueID, LocalTeamID, RootComponent { };

struct State
{
	std::uintptr_t Keys [0x7];
};

typedef struct EntityList
{
	std::uintptr_t Actor;
	std::uintptr_t MeshComponent;
	std::uintptr_t RootComponent;
}; static std::vector<EntityList> EnemyCollection {};

/// <summary>
/// 
/// </summary>
struct FLinearColor 
{
	float R;
	float G;
	float B;
	float A;
};

/// <summary>
/// 
/// </summary>
enum class EAresOutlineMode : uint8 
{
	None = 0,
	Outline = 1,
	Block = 2,
	Enemy = 3,
	AlwaysOutline = 4,
	AlwaysEnemy = 5,
	EAresOutlineMode_MAX = 6
};

/// <summary>
/// 
/// </summary>
class FVector
{
public:
	FVector ( ) : x ( 0.f ), y ( 0.f ), z ( 0.f )
	{

	}

	FVector ( float _x, float _y, float _z ) : x ( _x ), y ( _y ), z ( _z )
	{

	}
	~FVector ( )
	{

	}

	float x;
	float y;
	float z;

	inline float Dot ( FVector v )
	{
		return x * v.x + y * v.y + z * v.z;
	}

	inline float Distance ( FVector v )
	{
		float x = this->x - v.x;
		float y = this->y - v.y;
		float z = this->z - v.z;

		return sqrtf ( ( x * x ) + ( y * y ) + ( z * z ) ) * 0.03048f;
	}

	FVector operator+( FVector v )
	{
		return FVector ( x + v.x, y + v.y, z + v.z );
	}

	FVector operator-( FVector v )
	{
		return FVector ( x - v.x, y - v.y, z - v.z );
	}

	FVector operator*( float number ) const {
		return FVector ( x * number, y * number, z * number );
	}

	__forceinline float Magnitude ( ) const {
		return sqrtf ( x * x + y * y + z * z );
	}

	inline float Length ( )
	{
		return sqrtf ( ( x * x ) + ( y * y ) + ( z * z ) );
	}

	__forceinline FVector Normalize ( ) {
		FVector vector;
		float length = this->Magnitude ( );

		if ( length != 0 ) {
			vector.x = x / length;
			vector.y = y / length;
			vector.z = z / length;
		}
		else {
			vector.x = vector.y = 0.0f;
			vector.z = 1.0f;
		}
		return vector;
	}

	__forceinline FVector& operator+=( const FVector& v ) {
		x += v.x;
		y += v.y;
		z += v.z;
		return *this;
	}
};

FVector CameraLocation, CameraRotation { };
float FOVAngle { };

/// <summary>
/// 
/// </summary>
/// <param name="rot"></param>
/// <param name="origin"></param>
/// <returns></returns>
D3DMATRIX Matrix ( FVector rot, FVector origin )
{
	float radPitch = ( rot.x * float ( M_PI ) / 180.f );
	float radYaw = ( rot.y * float ( M_PI ) / 180.f );
	float radRoll = ( rot.z * float ( M_PI ) / 180.f );

	float SP = sinf ( radPitch );
	float CP = cosf ( radPitch );
	float SY = sinf ( radYaw );
	float CY = cosf ( radYaw );
	float SR = sinf ( radRoll );
	float CR = cosf ( radRoll );

	D3DMATRIX matrix;
	matrix.m [0][0] = CP * CY;
	matrix.m [0][1] = CP * SY;
	matrix.m [0][2] = SP;
	matrix.m [0][3] = 0.f;

	matrix.m [1][0] = SR * SP * CY - CR * SY;
	matrix.m [1][1] = SR * SP * SY + CR * CY;
	matrix.m [1][2] = -SR * CP;
	matrix.m [1][3] = 0.f;

	matrix.m [2][0] = -( CR * SP * CY + SR * SY );
	matrix.m [2][1] = CY * SR - CR * SP * SY;
	matrix.m [2][2] = CR * CP;
	matrix.m [2][3] = 0.f;

	matrix.m [3][0] = origin.x;
	matrix.m [3][1] = origin.y;
	matrix.m [3][2] = origin.z;
	matrix.m [3][3] = 1.f;

	return matrix;
}

/// <summary>
/// 
/// </summary>
struct FQuat
{
	float x;
	float y;
	float z;
	float w;
};

/// <summary>
/// 
/// </summary>
struct FTransform
{
	FQuat rot;
	FVector translation;
	char pad [4];
	FVector scale;
	char pad1 [4];

	D3DMATRIX ToMatrixWithScale ( )
	{
		D3DMATRIX m;
		m._41 = translation.x;
		m._42 = translation.y;
		m._43 = translation.z;

		float x2 = rot.x + rot.x;
		float y2 = rot.y + rot.y;
		float z2 = rot.z + rot.z;

		float xx2 = rot.x * x2;
		float yy2 = rot.y * y2;
		float zz2 = rot.z * z2;
		m._11 = ( 1.0f - ( yy2 + zz2 ) ) * scale.x;
		m._22 = ( 1.0f - ( xx2 + zz2 ) ) * scale.y;
		m._33 = ( 1.0f - ( xx2 + yy2 ) ) * scale.z;

		float yz2 = rot.y * z2;
		float wx2 = rot.w * x2;
		m._32 = ( yz2 - wx2 ) * scale.z;
		m._23 = ( yz2 + wx2 ) * scale.y;

		float xy2 = rot.x * y2;
		float wz2 = rot.w * z2;
		m._21 = ( xy2 - wz2 ) * scale.y;
		m._12 = ( xy2 + wz2 ) * scale.x;

		float xz2 = rot.x * z2;
		float wy2 = rot.w * y2;
		m._31 = ( xz2 + wy2 ) * scale.z;
		m._13 = ( xz2 - wy2 ) * scale.x;

		m._14 = 0.0f;
		m._24 = 0.0f;
		m._34 = 0.0f;
		m._44 = 1.0f;

		return m;
	}
};

/// <summary>
/// 
/// </summary>
struct FMinimalViewInfo 
{
	FVector Location; 
	FVector Rotation; 
	float FOV; 
};

/// <summary>
/// 
/// </summary>
/// <param name="pM1"></param>
/// <param name="pM2"></param>
/// <returns></returns>
D3DMATRIX MatrixMultiplication ( D3DMATRIX pM1, D3DMATRIX pM2 )
{
	D3DMATRIX pOut;
	pOut._11 = pM1._11 * pM2._11 + pM1._12 * pM2._21 + pM1._13 * pM2._31 + pM1._14 * pM2._41;
	pOut._12 = pM1._11 * pM2._12 + pM1._12 * pM2._22 + pM1._13 * pM2._32 + pM1._14 * pM2._42;
	pOut._13 = pM1._11 * pM2._13 + pM1._12 * pM2._23 + pM1._13 * pM2._33 + pM1._14 * pM2._43;
	pOut._14 = pM1._11 * pM2._14 + pM1._12 * pM2._24 + pM1._13 * pM2._34 + pM1._14 * pM2._44;
	pOut._21 = pM1._21 * pM2._11 + pM1._22 * pM2._21 + pM1._23 * pM2._31 + pM1._24 * pM2._41;
	pOut._22 = pM1._21 * pM2._12 + pM1._22 * pM2._22 + pM1._23 * pM2._32 + pM1._24 * pM2._42;
	pOut._23 = pM1._21 * pM2._13 + pM1._22 * pM2._23 + pM1._23 * pM2._33 + pM1._24 * pM2._43;
	pOut._24 = pM1._21 * pM2._14 + pM1._22 * pM2._24 + pM1._23 * pM2._34 + pM1._24 * pM2._44;
	pOut._31 = pM1._31 * pM2._11 + pM1._32 * pM2._21 + pM1._33 * pM2._31 + pM1._34 * pM2._41;
	pOut._32 = pM1._31 * pM2._12 + pM1._32 * pM2._22 + pM1._33 * pM2._32 + pM1._34 * pM2._42;
	pOut._33 = pM1._31 * pM2._13 + pM1._32 * pM2._23 + pM1._33 * pM2._33 + pM1._34 * pM2._43;
	pOut._34 = pM1._31 * pM2._14 + pM1._32 * pM2._24 + pM1._33 * pM2._34 + pM1._34 * pM2._44;
	pOut._41 = pM1._41 * pM2._11 + pM1._42 * pM2._21 + pM1._43 * pM2._31 + pM1._44 * pM2._41;
	pOut._42 = pM1._41 * pM2._12 + pM1._42 * pM2._22 + pM1._43 * pM2._32 + pM1._44 * pM2._42;
	pOut._43 = pM1._41 * pM2._13 + pM1._42 * pM2._23 + pM1._43 * pM2._33 + pM1._44 * pM2._43;
	pOut._44 = pM1._41 * pM2._14 + pM1._42 * pM2._24 + pM1._43 * pM2._34 + pM1._44 * pM2._44;

	return pOut;
}

/// <summary>
/// 
/// </summary>
/// <typeparam name="Template"></typeparam>
template<class Template>
class TArray
{
public:
	int Length ( ) const
	{
		return Count;
	}

	Template GetById ( std::int32_t Iteration )
	{
		return Read<Template> ( Data + Iteration * sizeof(Template) );
	}

protected:
	std::uint64_t Data;
	std::uint32_t Count;
};