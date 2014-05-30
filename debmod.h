#ifndef __DEBUGGER_MODULE__
#define __DEBUGGER_MODULE__

//
//
//      This is the base debmod_t class definition
//      From this class all debugger code must inherite and specialize
//
//      Some OS specific functions must be implemented:
//        bool init_subsystem();
//        bool term_subsystem();
//        debmod_t *create_debug_session();
//        int create_thread(thread_cb_t thread_cb, void *context);
//

#include <map>
#include <deque>
#include <pro.h>
#include <idd.hpp>
#include "consts.h"

extern debugger_t debugger;

struct name_info_t
{
  eavec_t addrs;
  qvector<char *> names;
  void clear(void)
  {
    addrs.clear();
    names.clear();
  }
};

// Very simple class to store pending events
enum queue_pos_t
{
  IN_FRONT,
  IN_BACK
};

struct eventlist_t : public std::deque<debug_event_t>
{
private:
  bool synced;
public:
  // save a pending event
  void enqueue(const debug_event_t &ev, queue_pos_t pos)
  {
    if ( pos != IN_BACK )
      push_front(ev);
    else
      push_back(ev);
  }

  // retrieve a pending event
  bool retrieve(debug_event_t *event)
  {
    if ( empty() )
      return false;
    // get the first event and return it
    *event = front();
    pop_front();
    return true;
  }
};

typedef int ioctl_handler_t(
  class rpc_engine_t *rpc,
  int fn,
  const void *buf,
  size_t size,
  void **poutbuf,
  ssize_t *poutsize);

int send_ioctl(rpc_engine_t *rpc, int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
void set_arm_thumb_modes(ea_t *addrs, int qty);

// Main class to represent a debugger module
class debmod_t
{
  char *debug_event_str(const debug_event_t *ev, char *buf, size_t bufsize);

protected:
  typedef std::map<int, regval_t> regval_map_t;
  qstring input_file_path;
  qvector<exception_info_t> exceptions;
  name_info_t dn_names;
  // Pending events. currently used only to store
  // exceptions that happen while attaching
  eventlist_t events;
  // The last event received via a successful get_debug_event()
  debug_event_t last_event;

  // appcall contexts
  struct call_context_t
  {
    regvals_t saved_regs;
    ea_t sp;
    ea_t ctrl_ea;
    bool regs_spoiled;
    call_context_t() : sp(BADADDR), ctrl_ea(BADADDR), regs_spoiled(false) {}
  };
  typedef qstack<call_context_t> call_contexts_t;
  typedef std::map<thid_t, call_contexts_t> appcalls_t;
  appcalls_t appcalls;

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
  {
    return ::send_ioctl(rpc, fn, buf, size, poutbuf, poutsize);
  }
  // If an IDC error occurs: we can not prepare an error message on the server
  // side because we do not have access to error strings (they are in ida.hlp).
  // We pass the error code to IDA (with eventual arguments) so it can prepare
  // a nice error message for the user
  void report_idc_error(ea_t ea, error_t code, ssize_t errval, const char *errprm)
  {
    return ::report_idc_error(rpc, ea, code, errval, errprm);
  }

  typedef std::map<ea_t, lowcnd_t> lowcnds_t;
  lowcnds_t cndmap;
  bool handling_lowcnd;
  bool evaluate_and_handle_lowcnd(debug_event_t *event);
  bool handle_lowcnd(lowcnd_t *lc, debug_event_t *event);

  // helper functions for programmatical single stepping
  virtual int dbg_perform_single_step(debug_event_t *event, const insn_t &cmd);
  virtual int dbg_freeze_threads_except(thid_t) { return 0; }
  virtual int dbg_thaw_threads_except(thid_t) { return 0; }
  int resume_app_and_get_event(debug_event_t *dev);

public:
  int debugger_flags;           // initialized by dbg_init()
  meminfo_vec_t old_areas;
  rpc_engine_t *rpc;
  bool debug_debugger;

  // Since 64-bit debuggers usually can debug 32-bit applications, we can not
  // rely on sizeof(ea_t) to detect the current address size. The following
  // variable should be used instead. It is initialized with 8 for 64-bit debuggers
  // but they should adjust it as soon as they learn that a 32-bit application
  // is being debugged.
  // For 32-bit debuggers it is initialized with 4.
  int addrsize;

  // indexes of sp and program counter registers.
  // Must be initialized by derived classes.
  int sp_idx, pc_idx;

  // Total number of registers.
  // Must be initialized by derived classes.
  int nregs;

  // Breakpoint code.
  // Must be initialized by derived classes.
  bytevec_t bpt_code;

  DECLARE_UD_REPORTING(msg, rpc);
  DECLARE_UD_REPORTING(warning, rpc);
  DECLARE_UD_REPORTING(error, rpc);

  // -----------------------------------
  // Constructors and destructors
  // -----------------------------------
  debmod_t();
  virtual ~debmod_t() { cleanup(); }

  // -----------------------------------
  // Debug names methods
  // -----------------------------------
  void clear_debug_names();
  name_info_t *get_debug_names();
  void save_debug_name(ea_t ea, const char *name);
  int set_debug_names();
  int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  // -----------------------------------
  // Utility methods
  // -----------------------------------
  void cleanup(void);
  char *debug_event_str(const debug_event_t *ev);
  AS_PRINTF(2, 3) void debdeb(const char *format, ...);
  AS_PRINTF(2, 3) bool deberr(const char *format, ...);
  bool same_as_oldmemcfg(const meminfo_vec_t &areas);
  void save_oldmemcfg(const meminfo_vec_t &areas);
  bool continue_after_last_event(bool handled = true);
  lowcnd_t *get_failed_lowcnd(thid_t tid, ea_t ea);
  // -----------------------------------
  // Shared methods
  // -----------------------------------
  virtual bool check_input_file_crc32(uint32 orig_crc);
  virtual const exception_info_t *find_exception(int code);
  virtual bool get_exception_name(int code, char *buf, size_t bufsize);

  // -----------------------------------
  // Methods to be implemented
  // -----------------------------------
  virtual int idaapi dbg_init(bool _debug_debugger) = 0;
  virtual void idaapi dbg_term(void) = 0;
  virtual int  idaapi dbg_process_get_info(int n,
    const char *input,
    process_info_t *info) = 0;
  virtual int  idaapi dbg_detach_process(void) = 0;
  virtual int  idaapi dbg_start_process(const char *path,
    const char *args,
    const char *startdir,
    int flags,
    const char *input_path,
    uint32 input_file_crc32) = 0;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_msecs) = 0;
  virtual int  idaapi dbg_attach_process(pid_t process_id, int event_id) = 0;
  virtual int  idaapi dbg_prepare_to_pause_process(void) = 0;
  virtual int  idaapi dbg_exit_process(void) = 0;
  virtual int  idaapi dbg_continue_after_event(const debug_event_t *event) = 0;
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty);
  virtual void idaapi dbg_stopped_at_debug_event(void) = 0;
  virtual int  idaapi dbg_thread_suspend(thid_t thread_id) = 0;
  virtual int  idaapi dbg_thread_continue(thid_t thread_id) = 0;
  virtual int  idaapi dbg_thread_set_step(thid_t thread_id) = 0;
  virtual int  idaapi dbg_read_registers(thid_t thread_id,
    int clsmask,
    regval_t *values) = 0;
  virtual int  idaapi dbg_write_register(thid_t thread_id,
    int reg_idx,
    const regval_t *value) = 0;
  virtual int  idaapi dbg_thread_get_sreg_base(thid_t thread_id,
    int sreg_value,
    ea_t *ea) = 0;
  virtual ea_t idaapi map_address(ea_t ea, const regval_t *, int /* regnum */) { return ea; }
  virtual int  idaapi dbg_get_memory_info(meminfo_vec_t &areas) = 0;
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size) = 0;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size) = 0;
  virtual int  idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) = 0;
  // for swbpts, len may be -1 (unknown size, for example arm/thumb mode) or bpt opcode length
  virtual int  idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len) = 0;
  virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) = 0;
  virtual int  idaapi dbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
  virtual int  idaapi dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds);
  virtual int  idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea);
  virtual int  idaapi dbg_open_file(const char *file, uint32 *fsize, bool readonly) = 0;
  virtual void idaapi dbg_close_file(int fn) = 0;
  virtual ssize_t idaapi dbg_read_file(int fn, uint32 off, void *buf, size_t size) = 0;
  virtual ssize_t idaapi dbg_write_file(int fn, uint32 off, const void *buf, size_t size) = 0;
  virtual int  idaapi handle_ioctl(int /*fn*/, const void* /*buf*/, size_t /*size*/,
                                   void** /*outbuf*/, ssize_t* /*outsize*/) { return 0; }
  virtual int  idaapi get_system_specific_errno(void) const; // this code must be acceptable by winerr()
  virtual bool idaapi dbg_update_call_stack(thid_t, call_stack_t *) { return false; }
  virtual ea_t idaapi dbg_appcall(
    ea_t /*func_ea*/,
    thid_t /*tid*/,
    const struct func_type_info_t * /*fti*/,
    int /*nargs*/,
    const struct regobjs_t * /*regargs*/,
    struct relobj_t * /*stkargs*/,
    struct regobjs_t * /*retregs*/,
    qstring *errbuf,
    debug_event_t * /*event*/,
    int /*flags*/);
  virtual int idaapi dbg_cleanup_appcall(thid_t /*tid*/);
  virtual bool idaapi write_registers(
    thid_t /*tid*/,
    int /*start*/,
    int /*count*/,
    const regval_t * /*values*/,
    const int * /*indices*/ = NULL) { return false; }
  // finalize appcall stack image
  // input: stack image contains the return address at the beginning
  virtual int finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &) { return 0; }
  virtual bool should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea);
  virtual bool preprocess_appcall_cleanup(thid_t, call_context_t &) { return true; }
  virtual int get_regidx(const char *regname, int *clsmask) = 0;
};

// some functions, per OS implemented
bool init_subsystem();
bool term_subsystem();
debmod_t *create_debug_session();

// processor specific init/term
void processor_specific_init(void);
void processor_specific_term(void);

// perform an action on all existing debugger modules
struct debmod_visitor_t
{
  virtual int visit(debmod_t *debmod) = 0;
};
int for_all_debuggers(debmod_visitor_t &v);

extern debmod_t *idc_debmod;
extern thid_t idc_thread;
extern bool ignore_sigint;

void lprintf(const char *format,...);
bool lock_begin();
bool lock_end();

#endif
