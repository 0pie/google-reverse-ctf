import angr
import claripy

base_addr = 0x00100000 # Elf64_Ehdr

success_addr = 0x0010111d # [s_SUCCESS]
failure_addr = 0X00101100 # [S_FAILURE]

flag_lenght = 15

project = angr.Project("./a.out", main_opts ={"base_addr" : base_address})
flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(flag_length)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b"\n")])

state = project.factory.full_init_state(
		args = [ "./a.out"],
		add_options = angr.options.unicorn,
		stdin = flag
	)

for c in flag_chars:
	state.solver.add(c >= ord("!"))
	state.solver.add(c <= ord("~"))

sim_manager = project.factory.simulation_manager(state)
sim_manager.explore(find = success_addr, avoid = failure_addr)

if len(sim.manager.found) > 0: 
	for found in sim_manager.found:
		print(found.posix.dumps(0))
# pwned
