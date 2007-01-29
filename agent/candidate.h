
#ifndef _CANDIDATE_H
#define _CANDIDATE_H

typedef enum candidate_type CandidateType;

enum candidate_type
{
  CANDIDATE_TYPE_HOST,
  CANDIDATE_TYPE_SERVER_REFLEXIVE,
  CANDIDATE_TYPE_PEER_REFLEXIVE,
  CANDIDATE_TYPE_RELAYED,
};


typedef struct _candidate Candidate;

struct _candidate
{
  CandidateType type;
  guint id;
  Address addr;
  Address base_addr;
  guint16 port;
  guint32 priority;
  guint stream_id;
  guint component_id;
  // guint generation;
  // gchar *foundation;
  UDPSocket sock;
};


Candidate *
candidate_new (CandidateType type);
void
candidate_free (Candidate *candidate);
gfloat
candidate_jingle_priority (Candidate *candidate);
guint32
candidate_ice_priority (Candidate *candidate);

#endif /* _CANDIDATE_H */

