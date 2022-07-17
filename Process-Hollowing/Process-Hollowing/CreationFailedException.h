#pragma once
#include "HollowingException.h"

class CreationFailedException : public HollowingException
{
public:
	using HollowingException::HollowingException;
};
