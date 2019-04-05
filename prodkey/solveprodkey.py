import angr
import claripy

def main():
    # Setup angr project and create a blank state at 0x400c99.
    p = angr.Project('./prodkey')
    state = p.factory.blank_state(addr=0x400c99)

    # Create a symbolic vector the size of 
    # what the flag should be and store in an
    # arbitrary location in memory.
    arg = claripy.BVS("arg", 0x1d*8)
    state.memory.store(0xd0000000, arg)

    # Fill rdi with a pointer to our symbolic variable.
    state.regs.rdi = 0xd0000000

    # Constraints to ensure a printable solution.
    def char(state, byte):
        return state.solver.And(byte <= '~', byte >= ' ')

    # Add the above constaint to each byte of the flag.
    for c in arg.chop(8):
        state.solver.add(char(state, c))

    sm = p.factory.simulation_manager(state)
    sm.explore(find=0x400deb)

    # Eval one
    #print(sm.found[0].solver.eval(arg, cast_to=bytes))

    # Eval ten
    #print(sm.found[0].solver.eval_upto(arg, 10, cast_to=bytes))

    # Eval 100
    print(sm.found[0].solver.eval_upto(arg, 100, cast_to=bytes))

if __name__ == "__main__":
    main()


