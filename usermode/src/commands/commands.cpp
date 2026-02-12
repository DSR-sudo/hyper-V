#include "commands.h"
#include <CLI/CLI.hpp>
#include <hypercall/hypercall_def.h>
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"
#include "../system/system.h"

#include <print>
#include <array>
#include <Windows.h>
#include <winternl.h>

#define d_invoke_command_processor(command) process_##command(##command)
#define d_initial_process_command(command) if (*##command) d_invoke_command_processor(command)
#define d_process_command(command) else if (*##command) d_invoke_command_processor(command)

template <class t>
t get_command_option(CLI::App* app, std::string option_name)
{
	auto option = app->get_option(option_name);

	return option->empty() == false ? option->as<t>() : t{};
}

CLI::Option* add_command_option(CLI::App* app, std::string option_name)
{
	return app->add_option(option_name);
}

CLI::Option* add_transformed_command_option(CLI::App* app, std::string option_name, CLI::Transformer& transformer)
{
	CLI::Option* option = add_command_option(app, option_name);

	return option->transform(transformer);
}

std::uint8_t get_command_flag(CLI::App* app, std::string flag_name)
{
	auto option = app->get_option(flag_name);

	return !option->empty();
}

CLI::Option* add_command_flag(CLI::App* app, std::string flag_name)
{
	return app->add_flag(flag_name);
}

CLI::App* init_rgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rgpm = app.add_subcommand("rgpm", "reads memory from a given guest physical address")->ignore_case();

	add_transformed_command_option(rgpm, "physical_address", aliases_transformer)->required();
	add_command_option(rgpm, "size")->check(CLI::Range(0, 8))->required();

	return rgpm;
}

void process_rgpm(CLI::App* rgpm)
{
	const std::uint64_t guest_physical_address = get_command_option<std::uint64_t>(rgpm, "physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(rgpm, "size");

	std::uint64_t value = 0;

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(&value, guest_physical_address, size);

	if (bytes_read == size)
	{
		std::println("value: 0x{:x}", value);
	}
	else
	{
		std::println("failed to read");
	}
}

CLI::App* init_wgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* wgpm = app.add_subcommand("wgpm", "writes memory to a given guest physical address")->ignore_case();

	add_transformed_command_option(wgpm, "physical_address", aliases_transformer)->required();
	add_command_option(wgpm, "value")->required();
	add_command_option(wgpm, "size")->check(CLI::Range(0, 8))->required();

	return wgpm;
}

void process_wgpm(CLI::App* wgpm)
{
	const std::uint64_t guest_physical_address = get_command_option<std::uint64_t>(wgpm, "physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(wgpm, "size");

	std::uint64_t value = get_command_option<std::uint64_t>(wgpm, "value");

	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(&value, guest_physical_address, size);

	if (bytes_written == size)
	{
		std::println("success in write");
	}
	else
	{
		std::println("failed to write");
	}
}

CLI::App* init_cgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* cgpm = app.add_subcommand("cgpm", "copies memory from a given source to a destination (guest physical addresses)")->ignore_case();

	add_transformed_command_option(cgpm, "destination_physical_address", aliases_transformer)->required();
	add_transformed_command_option(cgpm, "source_physical_address", aliases_transformer)->required();
	add_command_option(cgpm, "size")->required();

	return cgpm;
}

void process_cgpm(CLI::App* cgpm)
{
	const std::uint64_t guest_destination_physical_address = get_command_option<std::uint64_t>(cgpm, "destination_physical_address");
	const std::uint64_t guest_source_physical_address = get_command_option<std::uint64_t>(cgpm, "source_physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(cgpm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(buffer.data(), guest_source_physical_address, size);
	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(buffer.data(), guest_destination_physical_address, size);

	if ((bytes_read == size) && (bytes_written == size))
	{
		std::println("success in copy");
	}
	else
	{
		std::println("failed to copy");
	}
}

CLI::App* init_gvat(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* gvat = app.add_subcommand("gvat", "translates a guest virtual address to its corresponding guest physical address, with the given guest cr3 value")->ignore_case();

	add_transformed_command_option(gvat, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(gvat, "cr3", aliases_transformer)->required();

	return gvat;
}

void process_gvat(CLI::App* gvat)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(gvat, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(gvat, "cr3");

	const std::uint64_t physical_address = hypercall::translate_guest_virtual_address(virtual_address, cr3);

	std::println("physical address: 0x{:x}", physical_address);
}

CLI::App* init_rgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rgvm = app.add_subcommand("rgvm", "reads memory from a given guest virtual address (when given the corresponding guest cr3 value)")->ignore_case();

	add_transformed_command_option(rgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(rgvm, "cr3", aliases_transformer)->required();
	add_command_option(rgvm, "size")->check(CLI::Range(0, 8))->required();

	return rgvm;
}

void process_rgvm(CLI::App* rgvm)
{
	const std::uint64_t guest_virtual_address = get_command_option<std::uint64_t>(rgvm, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(rgvm, "cr3");
	const std::uint64_t size = get_command_option<std::uint64_t>(rgvm, "size");

	std::uint64_t value = 0;

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(&value, guest_virtual_address, cr3, size);

	if (bytes_read == size)
	{
		std::println("value: 0x{:x}", value);
	}
	else
	{
		std::println("failed to read");
	}
}

CLI::App* init_wgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* wgvm = app.add_subcommand("wgvm", "writes memory from a given guest virtual address (when given the corresponding guest cr3 value)")->ignore_case();

	add_transformed_command_option(wgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(wgvm, "cr3", aliases_transformer)->required();
	add_command_option(wgvm, "value")->required();
	add_command_option(wgvm, "size")->check(CLI::Range(0, 8))->required();

	return wgvm;
}

void process_wgvm(CLI::App* wgvm)
{
	const std::uint64_t guest_virtual_address = get_command_option<std::uint64_t>(wgvm, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(wgvm, "cr3");
	const std::uint64_t size = get_command_option<std::uint64_t>(wgvm, "size");

	std::uint64_t value = get_command_option<std::uint64_t>(wgvm, "value");

	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(&value, guest_virtual_address, cr3, size);

	if (bytes_written == size)
	{
		std::println("success in write at given address");
	}
	else
	{
		std::println("failed to write at given address");
	}
}

CLI::App* init_cgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* cgvm = app.add_subcommand("cgvm", "copies memory from a given source to a destination (guest virtual addresses) (when given the corresponding guest cr3 values)")->ignore_case();

	add_transformed_command_option(cgvm, "destination_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "destination_cr3", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_cr3", aliases_transformer)->required();
	add_command_option(cgvm, "size")->required();

	return cgvm;
}

void process_cgvm(CLI::App* wgvm)
{
	const std::uint64_t guest_destination_virtual_address = get_command_option<std::uint64_t>(wgvm, "destination_virtual_address");
	const std::uint64_t guest_destination_cr3 = get_command_option<std::uint64_t>(wgvm, "destination_cr3");

	const std::uint64_t guest_source_virtual_address = get_command_option<std::uint64_t>(wgvm, "source_virtual_address");
	const std::uint64_t guest_source_cr3 = get_command_option<std::uint64_t>(wgvm, "source_cr3");

	const std::uint64_t size = get_command_option<std::uint64_t>(wgvm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(buffer.data(), guest_source_virtual_address, guest_source_cr3, size);
	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(buffer.data(), guest_destination_virtual_address, guest_destination_cr3, size);

	if ((bytes_read == size) && (bytes_written == size))
	{
		std::println("success in copy");
	}
	else
	{
		std::println("failed to copy");
	}
}

CLI::App* init_akh(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* akh = app.add_subcommand("akh", "add a hook on specified kernel code (given the guest virtual address) (asmbytes in form: 0xE8 0x12 0x23 0x34 0x45)")->ignore_case();

	add_transformed_command_option(akh, "virtual_address", aliases_transformer)->required();
	add_command_option(akh, "--asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_option(akh, "--post_original_asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_flag(akh, "--monitor");

	return akh;
}

void process_akh(CLI::App* akh)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(akh, "virtual_address");

	std::vector<uint8_t> asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--asmbytes");
	const std::vector<uint8_t> post_original_asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--post_original_asmbytes");

	const std::uint8_t monitor = get_command_flag(akh, "--monitor");

	if (monitor == 1)
	{
		std::array<std::uint8_t, 9> monitor_bytes = {
			0x51, // push rcx
			0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
			0x0F, 0xA2, // cpuid
			0x59 // pop rcx
		};

		hypercall_info_t call_info = { };

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::log_current_state;

		*reinterpret_cast<std::uint32_t*>(&monitor_bytes[2]) = static_cast<std::uint32_t>(call_info.value);

		asm_bytes.insert(asm_bytes.end(), monitor_bytes.begin(), monitor_bytes.end());
	}

	const std::uint8_t hook_status = hook::add_kernel_hook(virtual_address, asm_bytes, post_original_asm_bytes);

	if (hook_status == 1)
	{
		std::println("success in hook");
	}
	else
	{
		std::println("failed to hook");
	}
}

CLI::App* init_rkh(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rkh = app.add_subcommand("rkh", "remove a previously placed hook on specified kernel code (given the guest virtual address)")->ignore_case();

	add_transformed_command_option(rkh, "virtual_address", aliases_transformer)->required();

	return rkh;
}

void process_rkh(CLI::App* rkh)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(rkh, "virtual_address");

	const std::uint8_t hook_removal_status = hook::remove_kernel_hook(virtual_address, 1);

	if (hook_removal_status == 1)
	{
		std::println("success in hook removal");
	}
	else
	{
		std::println("failed to remove hook");
	}
}

CLI::App* init_hgpp(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* hgpp = app.add_subcommand("hgpp", "hide a physical page's real contents from the guest")->ignore_case();

	add_transformed_command_option(hgpp, "physical_address", aliases_transformer)->required();

	return hgpp;
}

void process_hgpp(CLI::App* hgpp)
{
	const std::uint64_t physical_address = get_command_option<std::uint64_t>(hgpp, "physical_address");

	const std::uint64_t hide_status = hypercall::hide_guest_physical_page(physical_address);

	if (hide_status == 1)
	{
		std::println("success in hiding page");
	}
	else
	{
		std::println("failed to hide page");
	}
}

CLI::App* init_fl(CLI::App& app)
{
	CLI::App* fl = app.add_subcommand("fl", "flush trap frame logs from hooks")->ignore_case();

	return fl;
}

void process_fl(CLI::App* fl)
{
	constexpr std::uint64_t log_count = 100;
	constexpr std::uint64_t failed_log_count = -1;

	std::vector<trap_frame_log_t> logs(log_count);

	const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

	if (logs_flushed == failed_log_count)
	{
		std::println("failed to flush logs");
	}
	else if (logs_flushed == 0)
	{
		std::println("there are no logs to flush");
	}
	else
	{
		std::println("success in flushing logs ({}), outputting logs now:\n\n", logs_flushed);

		for (std::uint64_t i = 0; i < logs_flushed; i++)
		{
			const trap_frame_log_t& log = logs[i];

			if (log.rip == 0)
			{
				break;
			}

			std::println("{}. rip=0x{:X} rax=0x{:X} rcx=0x{:X}\nrdx=0x{:X} rbx=0x{:X} rsp=0x{:X} rbp=0x{:X}\nrsi=0x{:X} rdi=0x{:X} r8=0x{:X} r9=0x{:X}\nr10=0x{:X} r11=0x{:X} r12=0x{:X} r13=0x{:X} r14=0x{:X}\nr15=0x{:X} cr3=0x{:X}\n"
				,i, log.rip, log.rax, log.rcx, log.rdx, log.rbx, log.rsp, log.rbp, log.rsi, log.rdi, log.r8, log.r9, log.r10, log.r11, log.r12, log.r13, log.r14, log.r15, log.cr3);

			std::println("stack data:");
			
			for (const std::uint64_t stack_value : log.stack_data)
			{
				std::println("  0x{:X}", stack_value);
			}

			std::println();
		}
	}
}

CLI::App* init_hfpc(CLI::App& app)
{
	CLI::App* hfpc = app.add_subcommand("hfpc", "get hyperv-attachment's heap free page count")->ignore_case();

	return hfpc;
}

void process_hfpc(CLI::App* hfpc)
{
	const std::uint64_t heap_free_page_count = hypercall::get_heap_free_page_count();

	std::println("heap free page count: {}", heap_free_page_count);
}

CLI::App* init_log(CLI::App& app)
{
	CLI::App* log = app.add_subcommand("log", "pull and print text logs from hypervisor-attachment")->ignore_case();

	return log;
}

#include <thread>
#include <chrono>

void process_log_cmd(CLI::App* log)
{
	(void)log;

	bool logs_found = false;
	while (true)
	{
		std::vector<char> buffer(4 * 1024 + 1, 0); // extra byte for null terminator
		const std::uint64_t bytes_retrieved = hypercall::get_logs(buffer.data(), 4 * 1024);

		if (bytes_retrieved > 0)
		{
			if (!logs_found)
			{
				std::println("success in retrieving logs:");
				logs_found = true;
			}
			std::print("{}", buffer.data());

			// If we got less than requested, it means buffer is empty now
			if (bytes_retrieved < 4 * 1024)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				break;
			}
		}
		else
		{
			if (!logs_found) std::println("there are no logs to retrieve");
			break;
		}
	}
}

CLI::App* init_lkm(CLI::App& app)
{
	CLI::App* lkm = app.add_subcommand("lkm", "print list of loaded kernel modules")->ignore_case();

	return lkm;
}

void process_lkm(CLI::App* lkm)
{
	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		std::println("'{}' has a base address of: 0x{:x}, and a size of: 0x{:X}", module_name, module_info.base_address, module_info.size);
	}
}

CLI::App* init_kme(CLI::App& app)
{
	CLI::App* kme = app.add_subcommand("kme", "list the exports of a loaded kernel module (when given the name)")->ignore_case();

	add_command_option(kme, "module_name")->required();

	return kme;
}

void process_kme(CLI::App* kme)
{
	const std::string module_name = get_command_option<std::string>(kme, "module_name");

	if (sys::kernel::modules_list.contains(module_name) == false)
	{
		std::println("module not found");

		return;
	}

	const sys::kernel_module_t module = sys::kernel::modules_list[module_name];

	for (auto& [export_name, export_address] : module.exports)
	{
		std::println("{} = 0x{:X}", export_name, export_address);
	}
}

CLI::App* init_dkm(CLI::App& app)
{
	CLI::App* dkm = app.add_subcommand("dkm", "dump kernel module to a file on disk")->ignore_case();

	add_command_option(dkm, "module_name")->required();
	add_command_option(dkm, "output_directory")->required();

	return dkm;
}

void process_dkm(CLI::App* dkm)
{
	const std::string module_name = get_command_option<std::string>(dkm, "module_name");

	if (sys::kernel::modules_list.contains(module_name) == false)
	{
		std::println("module not found");

		return;
	}

	const std::string output_directory = get_command_option<std::string>(dkm, "output_directory");

	const std::uint8_t status = sys::kernel::dump_module_to_disk(module_name, output_directory);

	if (status == 1)
	{
		std::println("success in dumping module");
	}
	else
	{
		std::println("failed to dump module");
	}
}

std::wstring to_wstring(const std::string& value)
{
	return std::wstring(value.begin(), value.end());
}

std::wstring normalize_nt_path(const std::string& path)
{
	if (path.empty())
	{
		return L"\\??\\C:\\Windows\\System32\\ntdll.dll";
	}
	if (path.rfind("\\??\\", 0) == 0)
	{
		return to_wstring(path);
	}
	return L"\\??\\" + to_wstring(path);
}

std::uint8_t trigger_nt_open(const std::wstring& path)
{
	UNICODE_STRING unicode_path = {};
	RtlInitUnicodeString(&unicode_path, path.c_str());

	OBJECT_ATTRIBUTES object_attributes = {};
	InitializeObjectAttributes(&object_attributes, &unicode_path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	IO_STATUS_BLOCK io_status = {};
	HANDLE file_handle = nullptr;
	NTSTATUS status = NtOpenFile(&file_handle, FILE_READ_ATTRIBUTES, &object_attributes, &io_status,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE);

	if (status >= 0)
	{
		CloseHandle(file_handle);
		return 1;
	}

	return 0;
}

CLI::App* init_hprep(CLI::App& app)
{
	CLI::App* hprep = app.add_subcommand("hprep", "prepare manual hijack stage")->ignore_case();

	return hprep;
}

void process_hprep(CLI::App* hprep)
{
	(void)hprep;

	const std::uint64_t status = hypercall::prepare_manual_hijack();

	if (status == 1)
	{
		std::println("prepare requested");
	}
	else
	{
		std::println("prepare request failed");
	}
}

CLI::App* init_htrig(CLI::App& app)
{
	CLI::App* htrig = app.add_subcommand("htrig", "trigger manual hijack stage")->ignore_case();

	add_command_option(htrig, "path");

	return htrig;
}

void process_htrig(CLI::App* htrig)
{
	const std::string path = get_command_option<std::string>(htrig, "path");

	const std::uint64_t status = hypercall::trigger_manual_hijack();

	if (status != 1)
	{
		std::println("trigger request failed");
		return;
	}

	const std::wstring nt_path = normalize_nt_path(path);
	const std::uint8_t opened = trigger_nt_open(nt_path);

	if (opened == 1)
	{
		std::println("triggered kernel open");
	}
	else
	{
		std::println("kernel open failed");
	}
}

CLI::App* init_gva(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* gva = app.add_subcommand("gva", "get the numerical value of an alias")->ignore_case();

	add_transformed_command_option(gva, "alias_name", aliases_transformer)->required();

	return gva;
}

void process_gva(CLI::App* gva)
{
	const std::uint64_t alias_value = get_command_option<std::uint64_t>(gva, "alias_name");

	std::println("alias value: 0x{:X}", alias_value);
}

std::unordered_map<std::string, std::uint64_t> form_aliases()
{
	std::unordered_map<std::string, std::uint64_t> aliases = { { "current_cr3", sys::current_cr3 } };

	for (auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		aliases.insert({ module_name, module_info.base_address });
		aliases.insert(module_info.exports.begin(), module_info.exports.end());
	}

	return aliases;
}

void commands::process(const std::string command)
{
	if (command.empty() == true)
	{
		return;
	}

	CLI::App app;
	app.require_subcommand();

	sys::kernel::parse_modules();

	const std::unordered_map<std::string, std::uint64_t> aliases = form_aliases();

	CLI::Transformer aliases_transformer = CLI::Transformer(aliases, CLI::ignore_case);

	aliases_transformer.description(" can_use_aliases");

	CLI::App* rgpm = init_rgpm(app, aliases_transformer);
	CLI::App* wgpm = init_wgpm(app, aliases_transformer);
	CLI::App* cgpm = init_cgpm(app, aliases_transformer);
	CLI::App* gvat = init_gvat(app, aliases_transformer);
	CLI::App* rgvm = init_rgvm(app, aliases_transformer);
	CLI::App* wgvm = init_wgvm(app, aliases_transformer);
	CLI::App* cgvm = init_cgvm(app, aliases_transformer);
	CLI::App* akh = init_akh(app, aliases_transformer);
	CLI::App* rkh = init_rkh(app, aliases_transformer);
	CLI::App* gva = init_gva(app, aliases_transformer);
	CLI::App* hgpp = init_hgpp(app, aliases_transformer);
	CLI::App* fl = init_fl(app);
	CLI::App* hfpc = init_hfpc(app);
	CLI::App* log_cmd = init_log(app);
	CLI::App* lkm = init_lkm(app);
	CLI::App* kme = init_kme(app);
	CLI::App* dkm = init_dkm(app);
	CLI::App* hprep = init_hprep(app);
	CLI::App* htrig = init_htrig(app);

	try
	{
		app.parse(command);

		d_initial_process_command(rgpm);
		d_process_command(wgpm);
		d_process_command(cgpm);
		d_process_command(gvat);
		d_process_command(rgvm);
		d_process_command(wgvm);
		d_process_command(cgvm);
		d_process_command(akh);
		d_process_command(rkh);
		d_process_command(gva);
		d_process_command(hgpp);
		d_process_command(fl);
		d_process_command(hfpc);
		d_process_command(log_cmd);
		d_process_command(lkm);
		d_process_command(kme);
		d_process_command(dkm);
		d_process_command(hprep);
		d_process_command(htrig);
	}
	catch (const CLI::ParseError& error)
	{
		app.exit(error);
	}
}
