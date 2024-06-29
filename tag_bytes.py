# IBM i type tag statistics
# @author buherator
# @category IBMi
# @keybinding
# @menupath
# @toolbar

import ghidra.program.model.scalar.Scalar as Scalar
import logging

# Adjust to enable debug messages
logging.basicConfig(level=logging.INFO)

def findLoadImmediate(curr_instr, reg):
    for i in range(0, 10):
        curr_instr = curr_instr.getPrevious()
        if curr_instr is None:
            return None
        if (
            curr_instr.getMnemonicString().startswith("li")
            and curr_instr.getNumOperands() == 2
        ):
            target_ops = curr_instr.getDefaultOperandRepresentationList(0)
            op_reps = curr_instr.getDefaultOperandRepresentationList(1)
            for rep in op_reps:
                if type(rep) is Scalar and target_ops[0].equals(reg):
                    logging.debug("Instruction pair found :)")
                    logging.debug(" %s %s",curr_instr.getAddress(), curr_instr)
                    return rep.getValue()
    return None

def print_stats():
    for tag, count in stats.items():
        print("Tag: 0x%02X - %d instances found" % (tag, count))

stats = {}
instr = getFirstInstruction()

while instr is not None:
    if instr.getMnemonicString().startswith("rldicr"):
        src_ops=instr.getDefaultOperandRepresentationList(1)
        li = findLoadImmediate(instr, src_ops[0])
        if li is not None:
            logging.debug(" %s %s", instr.getAddress(), instr)
            if li not in stats:
                stats[li] = 0
            stats[li] = stats[li] + 1

    instr = instr.getNext()
print_stats()
