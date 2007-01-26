
#include <string.h>

#include <check.h>

#include <stun.h>

START_TEST (test_attribute_pack)
{
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *packed;
  guint length;

  length = stun_attribute_pack (attr, &packed);

  fail_unless (12 == length);
  fail_unless (NULL != packed);

  fail_unless (0 == memcmp (packed,
    "\x00\x01"          // type
    "\x00\x08"          // length
    "\x00\x01"          // padding, address family
    "\x09\x29"          // port
    "\x02\x03\x04\x05", // IP address
    length));
  g_free (packed);
  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_pack_unknown)
{
  /* can't create an unknown attribute directly, so create a MAPPED-ADDRESS
   * and change its type
   */
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *packed = NULL;
  guint length;

  attr->type = 0xff;
  length = stun_attribute_pack (attr, &packed);
  fail_unless (0 == length);
  fail_unless (NULL == packed);

  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_dump)
{
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *dump = stun_attribute_dump (attr);

  fail_unless (NULL != dump);
  fail_unless (0 == strcmp (dump, "MAPPED-ADDRESS 2.3.4.5:2345"));
  g_free (dump);
  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_dump_unknown)
{
  gchar *dump;

  StunAttribute *attr = stun_attribute_unpack (4,
    "\x00\xff" // type
    "\x00\x00" // length
    );

  dump = stun_attribute_dump (attr);
  fail_unless (0 == strcmp (dump, "UNKNOWN (255)"));
  g_free (dump);
  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_unpack)
{
  StunAttribute *attr = stun_attribute_unpack (12,
    "\x00\x01"         // type
    "\x00\x08"         // length
    "\x00\x01"         // padding, address family
    "\x09\x29"         // port
    "\x02\x03\x04\x05" // IP address
    );

  fail_unless (NULL != attr);
  fail_unless (attr->type == STUN_ATTRIBUTE_MAPPED_ADDRESS);
  fail_unless (attr->address.af == 1);
  fail_unless (attr->address.port == 2345);
  fail_unless (attr->address.ip == 0x02030405);
  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_unpack_unknown)
{
  StunAttribute *attr = stun_attribute_unpack (8,
      "\x00\xff" // type
      "\x00\x04" // length
      "\xff\xff" // some data
      "\xff\xff"
      );

  fail_unless (NULL != attr);
  fail_unless (attr->type == 0xff);
  stun_attribute_free (attr);
}
END_TEST

START_TEST (test_attribute_unpack_wrong_length)
{
  StunAttribute *attr;

  // attributes must be at least 4 bytes long
  attr = stun_attribute_unpack (0, NULL);
  fail_unless (NULL == attr);

  // attributes must aligned to 32 bits
  attr = stun_attribute_unpack (33, NULL);
  fail_unless (NULL == attr);

  attr = stun_attribute_unpack (8,
      "\x00\x01" // type = MAPPED-ADDRESS
      "\x00\x04" // length = 4 (invalid!)
      "\x00\x01" // padding, address family
      "\x09\x29" // port
      );
  fail_unless (NULL == attr);
}
END_TEST

START_TEST (test_message_pack)
{
  StunMessage *msg = stun_message_binding_request_new ();
  gchar *packed;
  guint length;

  memcpy (msg->transaction_id,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
  msg->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);
  length = stun_message_pack (msg, &packed);

  fail_unless (packed != NULL);
  fail_unless (length == 32);
  fail_unless (0 == memcmp (packed + 0, "\x00\x01", 2));
  fail_unless (0 == memcmp (packed + 2, "\x00\x0c", 2));
  fail_unless (0 == memcmp (packed + 4,
    "\x00\x01\x02\x03"
    "\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b"
    "\x0c\x0d\x0e\x0f", 16));
  fail_unless (0 == memcmp (packed + 20,
    "\x00\x01"          // type
    "\x00\x08"          // length
    "\x00\x01"          // padding, address family
    "\x09\x29"          // port
    "\x02\x03\x04\x05", // IP address
    12));

  g_free (packed);
  stun_message_free (msg);
}
END_TEST

START_TEST (test_message_dump)
{
  StunMessage *msg = stun_message_binding_request_new ();
  gchar *dump;

  msg->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);

  dump = stun_message_dump (msg);
  fail_unless (NULL != dump);
  fail_unless (0 == strcmp (dump,
    "BINDING-REQUEST 00000000:00000000:00000000:00000000\n"
    "  MAPPED-ADDRESS 2.3.4.5:2345"));
  g_free (dump);
  stun_message_free (msg);
}
END_TEST

START_TEST (test_message_unpack)
{
  StunMessage *msg = stun_message_unpack (32,
    "\x00\x01"         // type
    "\x00\x0c"         // length
    "\x00\x01\x02\x03" // transaction ID
    "\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b"
    "\x0c\x0d\x0e\x0f"
    "\x00\x01"         // attr1 type
    "\x00\x08"         // attr1 length
    "\x00\x01"         // padding, address family
    "\x09\x29"         // port
    "\x02\x03\x04\x05" // IP address
    );

  fail_unless (msg->type == STUN_MESSAGE_BINDING_REQUEST);
  fail_unless (msg->attributes[0] != NULL);
  fail_unless (msg->attributes[0]->type == STUN_ATTRIBUTE_MAPPED_ADDRESS);
  fail_unless (msg->attributes[0]->address.port == 2345);
  fail_unless (msg->attributes[0]->address.ip == 0x02030405);
  fail_unless (msg->attributes[1] == NULL);
  stun_message_free (msg);
}
END_TEST

Suite *
stun_suite (void)
{
  Suite *suite;
  TCase *tcase;

  suite = suite_create ("STUN");

  tcase = tcase_create ("attribute pack");
  tcase_add_test (tcase, test_attribute_pack);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute pack unknown");
  tcase_add_test (tcase, test_attribute_pack_unknown);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute dump");
  tcase_add_test (tcase, test_attribute_dump);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute dump unknown");
  tcase_add_test (tcase, test_attribute_dump_unknown);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute unpack");
  tcase_add_test (tcase, test_attribute_unpack);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute unpack unknown");
  tcase_add_test (tcase, test_attribute_unpack_unknown);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("attribute unpack unknown wrong length");
  tcase_add_test (tcase, test_attribute_unpack_wrong_length);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("message pack");
  tcase_add_test (tcase, test_message_pack);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("message dump");
  tcase_add_test (tcase, test_message_dump);
  suite_add_tcase (suite, tcase);

  tcase = tcase_create ("message unpack");
  tcase_add_test (tcase, test_message_unpack);
  suite_add_tcase (suite, tcase);

  return suite;
}

int
main (void)
{
  Suite *suite;
  SRunner *runner;
  int failures;

  suite = stun_suite ();
  runner = srunner_create (suite);
  srunner_run_all (runner, CK_NORMAL | CK_NOFORK);
  failures = srunner_ntests_failed (runner);
  srunner_free (runner);

  return (failures == 0) ? 0 : 1;
}

