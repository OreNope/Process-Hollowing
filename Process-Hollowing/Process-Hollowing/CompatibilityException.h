#pragma once
#include "HollowingException.h"

class CompatibilityException : public HollowingException
{
public:
	using HollowingException::HollowingException;
};
