
#include "component.h"

Component *
component_new (
  G_GNUC_UNUSED
  ComponentType type)
{
  Component *component;

  component = g_slice_new0 (Component);
  component->id = 1;
  return component;
}


void
component_free (Component *cmp)
{
  GSList *i;

  for (i = cmp->local_candidates; i; i = i->next)
    {
      NiceCandidate *candidate = i->data;

      nice_candidate_free (candidate);
    }

  for (i = cmp->remote_candidates; i; i = i->next)
    {
      NiceCandidate *candidate = i->data;

      nice_candidate_free (candidate);
    }

  g_slist_free (cmp->local_candidates);
  g_slist_free (cmp->remote_candidates);
  g_slice_free (Component, cmp);
}

