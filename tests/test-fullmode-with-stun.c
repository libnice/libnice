#include <gio/gio.h>

int
main (int argc, char ** argv)
{
   int retval = 0;
   char *stund;
   char *test_fullmode;
   GSubprocess *stund_proc, *test_subprocess;
   const gchar NICE_STUN_SERVER[] = "127.0.0.1";
   const gchar NICE_STUN_SERVER_PORT[] = "3800";
   GError *gerr = NULL;

   if (argc < 3) {
         g_printerr ("Usage: %s <stund path> <test fullmode path>\n",
                     argv[0]);
         return 77;
   }

   stund = argv[1];
   test_fullmode = argv[2];

   g_print ("Starting ICE full-mode with STUN unit test.\n");
   g_print ("Launching %s on port %s.\n", stund, NICE_STUN_SERVER_PORT);


   stund_proc = g_subprocess_new (G_SUBPROCESS_FLAGS_NONE, &gerr,
                                  stund, NICE_STUN_SERVER_PORT, NULL);

   g_usleep(G_USEC_PER_SEC);

   g_setenv("NICE_STUN_SERVER", NICE_STUN_SERVER, TRUE);
   g_setenv("NICE_STUN_SERVER_PORT", NICE_STUN_SERVER_PORT, TRUE);

   g_print ("Running test fullmode as %s\n", test_fullmode);
   test_subprocess = g_subprocess_new (G_SUBPROCESS_FLAGS_NONE, &gerr,
                                       test_fullmode, NULL);
   g_assert_no_error (gerr);
   g_subprocess_wait (test_subprocess, NULL, &gerr);
   g_assert_no_error (gerr);
   retval = g_subprocess_get_exit_status (test_subprocess);
   g_print ("Test process returned %d\n", retval);
   g_object_unref (test_subprocess);
 
   g_subprocess_force_exit (stund_proc);
   g_subprocess_wait (stund_proc, NULL, &gerr);
   g_assert_no_error (gerr);
   g_object_unref(stund_proc);

   return retval;
}
