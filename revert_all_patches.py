import idautils
import ida_bytes
import ida_segment

# 使用IDA Pro 9.0 beta分析有的mach-o文件时不知为何默认会添加一堆patch，而且在IDA的界面中无法全部移除，这会导致添加我们自己patch后的程序不能正常运行
# 这个脚本的作用是还原所有patches
# 使用方法：分析完成后加载这个脚本

# When analyzing some mach-o files with IDA Pro 9.0 beta, a weird thing is that some patches will be added by default and cannot be removed from IDA's interface, which will cause the program after adding our own patches to not work properly
# The function of this script is to revert all patches
# Usage: Load this script after the analysis is complete

count = 0

def revert_patch_cb(ea, fpos, org_val, patch_val):
    global count

    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg, 1)
    print("[revert_all_patches] seg: " + seg_name + " 0x%x: original 0x%x, patched 0x%x" % (ea, org_val, patch_val))
    ida_bytes.revert_byte(ea)
    print("[revert_all_patches] seg: " + seg_name + " 0x%x: reverted to 0x%x" % (ea, org_val))
    count += 1
    return 0

segs = list(idautils.Segments())

start = segs[0]

last_seg = ida_segment.getseg(segs[-1])

end = last_seg.end_ea

ida_bytes.visit_patched_bytes(start, end, revert_patch_cb)

if count > 0:
    print("[revert_all_patches] Reverted %d patches" % count)
else:
    print("[revert_all_patches] No patches to revert")
