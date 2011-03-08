import dtrace
import time

d = dtrace.DtraceConsumer()
d.strcompile("""
syscall:::entry
{
self->syscall_entry_ts[probefunc] = vtimestamp;
}
syscall:::return
/self->syscall_entry_ts[probefunc]/
{

@time[probefunc] = lquantize((vtimestamp - self->syscall_entry_ts[probefunc] ) / 1000, 0, 512, 1);
self->syscall_entry_ts[probefunc] = 0;
}
""")
d.go()
def construct_aggregation(dtrace_handle):
    aggregation = {}
    def construction_callback(var_id, key, val):
        aggregation[key[0]] = val
    dtrace_handle.aggwalk(construction_callback)
    return aggregation
count = 0
while True:
    print "-------%d-------" % count
    count += 1
    print construct_aggregation(d)
    time.sleep(1)
d.stop()
