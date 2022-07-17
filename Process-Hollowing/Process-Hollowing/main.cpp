#include "Hollowing.h"

enum CommandLineArgs
{
	PROC_NAME,
	HOST_PATH,
	PAYLOAD_PATH
};

constexpr int REQUIRED_NUM_OF_ARGS = 3;

int main(int argc, char* argv[])
{
	if (argc != REQUIRED_NUM_OF_ARGS)
	{
		std::cerr << "Usage: " << argv[PROC_NAME] << " [host_path] [payload_path]" << std::endl;
		std::cin.get();
		return 1;
	}

	Hollowing hollowing(argv[HOST_PATH], argv[PAYLOAD_PATH]);

	hollowing.hollow();

	std::cin.get();

	return 0;
}
