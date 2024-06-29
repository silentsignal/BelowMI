# IBM i LQ mask statistics
# @author buherator
# @category IBMi
# @keybinding
# @menupath
# @toolbar

import ghidra.program.model.scalar.Scalar as Scalar
import logging

# Adjust to enable debug messages
logging.basicConfig(level=logging.INFO)


def print_stats():
    for mask, count in stats.items():
        print("TD Mask: %s - %d instances found" % (bin(mask), count))


stats = {}
instr = getFirstInstruction()

while instr is not None:
    if instr.getMnemonicString().startswith("td") and instr.getNumOperands() == 3:
        mask_ops = instr.getDefaultOperandRepresentationList(0)
        for val in mask_ops:
            if type(val) is Scalar:
                value = val.getValue()
                logging.debug(" %s %s", instr.getAddress(), instr)
                if value not in stats:
                    stats[value] = 0
                stats[value] += 1
    instr = instr.getNext()

print_stats()
