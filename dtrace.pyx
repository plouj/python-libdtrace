from cython import sizeof
from libc.stdint cimport int64_t, uint64_t, uint16_t, int32_t, uint32_t, uint8_t
cdef extern from "sys/int_limits.h":
    cdef int64_t INT64_MAX
    cdef uint32_t UINT32_MAX
    cdef uint64_t UINT16_MAX
    cdef int64_t INT64_MIN
cdef extern from "sys/types.h":
    ctypedef char * caddr_t
cdef extern from "dtrace-fix.h":
    pass
cdef extern from "sys/processor.h":
    ctypedef int processorid_t
cdef extern from "dtrace.h":
    cdef enum variousStuff:
        DTRACE_AGGWALK_ERROR = -1
        DTRACE_VERSION = 3
        DTRACE_AGGWALK_REMOVE = 5
        DTRACEACT_DIFEXPR = 1 #/* action is DIF expression */
        DTRACEACT_AGGREGATION = 0x0700
        DTRACEAGG_LQUANTIZE = (DTRACEACT_AGGREGATION + 8)

    ctypedef enum dtrace_probespec_t:
        DTRACE_PROBESPEC_NONE = -1
        DTRACE_PROBESPEC_PROVIDER = 0
        DTRACE_PROBESPEC_MOD
        DTRACE_PROBESPEC_FUNC
        DTRACE_PROBESPEC_NAME

    #from sys/dtrace.h:
    cdef uint16_t DTRACE_LQUANTIZE_STEP(long x)
    cdef uint16_t DTRACE_LQUANTIZE_LEVELS(long x)
    cdef int32_t DTRACE_LQUANTIZE_BASE(long x)

    ctypedef struct dtrace_hdl_t:
        pass
    ctypedef struct dtrace_prog_t:
        pass
    ctypedef struct dtrace_probespec_t:
        pass
    ctypedef struct dtrace_proginfo_t:
        pass
    ctypedef int64_t dtrace_aggvarid_t
    ctypedef uint16_t dtrace_actkind_t
    ctypedef struct dtrace_recdesc_t:
        #...from sys/dtrace.h
        dtrace_actkind_t dtrd_action		#/* kind of action */
        uint32_t dtrd_size			#/* size of record */
        uint32_t dtrd_offset			#/* offset in ECB's data */
        #...
    ctypedef struct dtrace_aggdesc_t:
        #...from sys/dtrace.h
        dtrace_aggvarid_t dtagd_varid
        int dtagd_nrecs			#/* number of records */
        dtrace_recdesc_t dtagd_rec[1]		#/* record descriptions */
        #...
    ctypedef struct dtrace_aggdata_t:
        #...
        dtrace_aggdesc_t *dtada_desc		#/* aggregation description */
        caddr_t dtada_data			#/* pointer to raw data */
        #...

    ctypedef int dtrace_aggregate_f(dtrace_aggdata_t *aggdata, void *arg)
    dtrace_hdl_t *dtrace_open(int version, int flags, int *error)
    void dtrace_close(dtrace_hdl_t *handle)
    dtrace_prog_t *dtrace_program_strcompile(
        dtrace_hdl_t *handle, char *program_text,
        dtrace_probespec_t spec, unsigned int flags, int argc, char *argv[])
    char *dtrace_errmsg(dtrace_hdl_t *handle, int error)
    int dtrace_errno(dtrace_hdl_t *handle)
    int dtrace_program_exec(dtrace_hdl_t *handle, dtrace_prog_t *program,
                            dtrace_proginfo_t *info)
    int dtrace_go(dtrace_hdl_t *handle)
    int dtrace_stop(dtrace_hdl_t *handle)
    int dtrace_setopt(dtrace_hdl_t *handle, char *option, char *value)
    int dtrace_aggregate_snap(dtrace_hdl_t *handle)
    int dtrace_aggregate_walk(dtrace_hdl_t *handle, dtrace_aggregate_f *func, void *args)
    int dtrace_status(dtrace_hdl_t *handle)

    ctypedef struct dtrace_dropdata_t:
        dtrace_hdl_t *dtdda_handle		#/* handle to DTrace library */
        processorid_t dtdda_cpu		#/* CPU, if any */
        uint64_t dtdda_drops			#/* number of drops */
        uint64_t dtdda_total			#/* total drops */
        char *dtdda_msg			#/* preconstructed message */

    ctypedef int dtrace_handle_drop_f(dtrace_dropdata_t *dropinfo, void *arg)
    int dtrace_handle_drop(dtrace_hdl_t *handler, dtrace_handle_drop_f *drophandler, void *arg)

cdef class DtraceConsumer:
    cdef dtrace_hdl_t *dhandle
    cdef drop_handler

    def __init__(self):
        cdef int err
        self.dhandle = dtrace_open(DTRACE_VERSION, 0, &err)
        if self.dhandle == NULL:
            raise Exception(dtrace_errmsg(NULL, err))

        # Set our buffer size and aggregation buffer size to the de facto
        # standard of 4M.

        if dtrace_setopt(self.dhandle, "bufsize", "4m") != 0:
            raise Exception(dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

        if dtrace_setopt(self.dhandle, "aggsize", "4m") != 0:
            raise Exception(dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

    def __del__(self):
        dtrace_close(self.dhandle)

    cpdef strcompile(self, char *program_text):
       """compile supplied text into a D program
       """
       cdef dtrace_prog_t *dtrace_program
       dtrace_program = dtrace_program_strcompile(
           self.dhandle, program_text, DTRACE_PROBESPEC_NAME,
           0, 0, NULL)
       if dtrace_program == NULL:
           raise Exception("couldn't compile '%s': %s\n" %
                           (program_text,
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle))))

       cdef dtrace_proginfo_t info
       if (dtrace_program_exec(self.dhandle, dtrace_program, &info) == -1):
           raise Exception("couldn't execute '%s': %s\n" %
                           (program_text,
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle))))

    cpdef go(self):
        """enable enable tracing of the previously compiled D program
        """
        if dtrace_go(self.dhandle) == -1:
            raise Exception("couldn't enable tracing: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

    cpdef stop(self):
        """enable enable tracing of the previously compiled D program
        """
        if dtrace_stop(self.dhandle) == -1:
            raise Exception("couldn't disable tracing: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

    cpdef set_drop_handler(self, user_func):
        """Setup a function to handle buffer drops
        """
        self.drop_handler = user_func # save the function reference so
        # that it doesn't go out of scope
        if dtrace_handle_drop(self.dhandle, c_drop_handler, <void *>self) != 0:
            raise Exception("couldn't setup the drop handling function: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

    cpdef aggwalk(self, func):
        """
        Snapshot and iterate over all aggregation data accumulated
        since the last call to aggwalk() (or the call to go() if
        aggwalk() has not been called).  For each aggregate record,
        func will be passed three arguments: varid, key, value
        """

        if dtrace_aggregate_snap(self.dhandle) != 0:
            raise Exception("couldn't snapshot aggregate: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))
        # C compiler generates a warning about type of agg_walk()
        # ignore it unless problems arise

        # it is important to do this on a regular basis because it calls the DTRACEIOC_STATUS ioctl
        # if we don't do it for about 30 seconds, the kernel will send a kill signal
        if dtrace_status(self.dhandle) == -1:
            raise Exception("couldn't get status: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

        if dtrace_aggregate_walk(self.dhandle, &c_aggwalk, <void *>func) != 0:
            raise Exception("couldn't walk aggregate: %s\n" %
                            dtrace_errmsg(self.dhandle, dtrace_errno(self.dhandle)))

cdef int c_drop_handler(dtrace_dropdata_t *dropinfo, void *arg):
    self_ref = <DtraceConsumer?>arg # get the reference to the dtrace class
    if self_ref.drop_handler != None:
        # call the user-defined drop handler
        return self_ref.drop_handler(dropinfo.dtdda_cpu, dropinfo.dtdda_drops, dropinfo.dtdda_total, dropinfo.dtdda_msg)
    else:
        print "python-libdtrace detected: %s" % dropinfo.dtdda_msg
        return 0

cdef int c_aggwalk(dtrace_aggdata_t *aggdata, void *arg):
    """dtrace_aggregate_walk() from libdtrace actually calls this C
    function for every record in the aggregation
    """
    description = aggdata.dtada_desc
    cdef int variable_id = description.dtagd_varid

    key = []
    val = None
    cdef dtrace_recdesc_t *rec
    cdef uint64_t arg2
    cdef int64_t *data
    for i in range(1, description.dtagd_nrecs - 1):
        rec = &description.dtagd_rec[i]
        address = aggdata.dtada_data + rec.dtrd_offset
        key.append(record(rec, address))

    aggrec = &description.dtagd_rec[description.dtagd_nrecs - 1]
    action = aggrec.dtrd_action
    # DTRACEAGG_LLQUANTIZE would be similar to this but with a more complicated ranges_llquantize()
    if action == DTRACEAGG_LQUANTIZE:
        lquantize = []
        data = <int64_t *>(aggdata.dtada_data + aggrec.dtrd_offset)
        agg_arg = data[0]
        levels = (aggrec.dtrd_size / sizeof (uint64_t)) - 1
        ranges = ranges_lquantize(agg_arg)
        for i in range(0,levels):
            if data[i+1]:
                lquantize.append((ranges[i], data[i+1]))
        val = lquantize
    else:
        raise Exception("Aggregation type (action) %d is not supported" % action)

    # extract the user's callback Python function from our arguments and call it
    function = <object>arg
    function(variable_id, key, val)
    # we have to return DTRACE_AGGWALK_REMOVE to cause
    # dtrace_aggregate_walk() keep calling us until the end of the
    # aggregate
    return DTRACE_AGGWALK_REMOVE

cdef record(dtrace_recdesc_t *rec, caddr_t address):
    action = rec.dtrd_action
    if action == DTRACEACT_DIFEXPR:
        if rec.dtrd_size == sizeof(uint64_t):
            return (<int64_t *>address)[0]
        elif rec.dtrd_size == sizeof(uint32_t):
            return (<int32_t *>address)[0]
        elif rec.dtrd_size == sizeof(uint16_t):
            return (<uint16_t *>address)[0]
        elif rec.dtrd_size == sizeof(uint8_t):
            return (<uint8_t *>address)[0]
        else:
            return (<char *>address)
    else:
        raise Exception("Unsuppored action type %d" % action)

cdef ranges_lquantize(uint64_t arg):
    """Generate a list of ranges based on the argument passed to the lquantize() function
    """
    cdef long base = DTRACE_LQUANTIZE_BASE(arg)
    cdef long step = DTRACE_LQUANTIZE_STEP(arg)
    cdef long levels = DTRACE_LQUANTIZE_LEVELS(arg)
    ranges = []

    for i in range(0, levels+2):
        if i == 0:
            min = INT64_MIN
        else:
            min = base + ((i - 1) * step)

        if i > levels:
            max = INT64_MAX
        else:
            max = base + (i * step) - 1
        # insert() guarantees that indexes in ranges match indexes in data,
        # but could have used append() just as well
        ranges.insert(i, ((min, max)))

    # TODO cache the ranges for performance similar to libdtrace.cc
    return ranges
