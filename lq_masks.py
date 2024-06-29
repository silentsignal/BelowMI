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
        print("LQ Mask: 0x%X - %d instances found" % (mask, count))

    for lq_mask, txer in pair_stats.items():
        for tx_mask, count in txer.items():
            print(
                "LQ mask: 0x%X with TXER mask 0x%X - %d instances"
                % (lq_mask, tx_mask, count)
            )


stats = {}
pair_stats = {}
instr = getFirstInstruction()
last_lq = None

while instr is not None:
    if instr.getMnemonicString().startswith("lq") and instr.getNumOperands() == 3:
        mask_ops = instr.getDefaultOperandRepresentationList(2)
        for val in mask_ops:
            if type(val) is Scalar:
                value = val.getValue()
                logging.debug(" %s %s", instr.getAddress(), instr)
                if value not in stats:
                    stats[value] = 0
                stats[value] += 1
                last_lq = (instr.getAddress(), value)
    if (
        last_lq is not None
        and instr.getMnemonicString().startswith("txer")
        and instr.getNumOperands() == 3
    ):
        mask_ops = instr.getDefaultOperandRepresentationList(2)
        for val in mask_ops:
            if type(val) is Scalar:
                value = val.getValue()
                logging.debug(" %s %s", instr.getAddress(), instr)
                if last_lq[1] not in pair_stats:
                    pair_stats[last_lq[1]] = {}
                ps = pair_stats[last_lq[1]]
                if value not in ps:
                    ps[value] = 0
                ps[value] += 1
                last_lq = None
    instr = instr.getNext()

print_stats()
