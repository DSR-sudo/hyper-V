#include <iostream>
#include <thread>
#include <string>
#include <print>
#include <Windows.h>

#include "commands/commands.h"
#include "hook/hook.h"
#include "system/system.h"

std::int32_t main()
{
    if (sys::set_up() == 0)
    {
        std::system("pause");

        return 1;
    }

    std::println("[Info] Hyper-reV Client started. Entering silent command loop.");

	while (true)
	{
		std::print("> ");

		std::string command = { };
		std::getline(std::cin, command);

		if (command == "exit")
		{
			break;
		}
			
		commands::process(command);

		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}

	sys::clean_up();

	return 0;
}
