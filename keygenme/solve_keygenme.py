import angr
import claripy

# Runtime: ~10 minutes

def main():
    p = angr.Project('./keygenme')

    # Hook the strlen function
    def sim_strlen(state):
        state.regs.rax = 16

    p.hook('strlen', sim_strlen)

    # Create entry point at where the key is
    # verified.
    state = p.factory.entry_state(addr=0x400aa5)

    # Create a 16-byte symbolic bitvector
    # and store it on the stack.
    arg = claripy.BVS('arg', 16*8)
    state.memory.store(state.regs.rbp-0xc0, arg)

    # Create simulation_manager, find a success state
    # and solve for the solution.
    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=0x400ab8)

    print(simgr)

    if simgr.found:
        print(simgr.found[0].solver.eval(arg, cast_to=bytes))

if __name__ == "__main__":
    main()