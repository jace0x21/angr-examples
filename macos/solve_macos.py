import angr
import claripy
import pdb

# An example of solving a simple Mach-O crackme
# despite the lack of support in angr.

def main():
    arg = claripy.BVS('sym_arg', 8 * 4)
    project = angr.Project('./macos')

    # Hook libc library calls.
    # This would be done automatically for an ELF
    # but support for Mach-Os is limited in angr.
    project.hook(0x100000f76, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(0x100000f70, angr.SIM_PROCEDURES['libc']['atoi']())

    state = project.factory.entry_state()

    simgr = project.factory.simulation_manager(state)

    # Explore using the simulation_manager until we find
    # a state where the string "WIN" can be found in stdout.
    simgr.explore(find=lambda s: b"WIN" in s.posix.dumps(1))

    # This will give us an iPython shell to solve for the flag.
    pdb.set_trace()

    ## From this point you can evaluate for each symbolic variable created
    ## by angr and one of them will be your flag.

if __name__ == "__main__":
    main()