package crlenforcer

import "errors"

// ---------------------------------------------------------------------------
// Erreurs sentinelles
// ---------------------------------------------------------------------------

// ErrNoCRLDistributionPoint est retournée lorsqu'un certificat ne déclare
// aucun point de distribution CRL. Sous une politique fail-closed, ceci est
// traité comme un rejet explicite et non comme une erreur technique.
var ErrNoCRLDistributionPoint = errors.New("certificate has no CRL distribution points")

// ErrCRLUnavailable signale que le CRL en cache est périmé (ou absent) et que
// son rafraîchissement a échoué. Dans ce cas, la requête est systématiquement
// rejetée : aucune donnée de révocation périmée n'est jamais utilisée pour
// autoriser un certificat.
var ErrCRLUnavailable = errors.New("CRL is stale or missing and could not be refreshed")
