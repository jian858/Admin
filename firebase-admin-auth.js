/* Firebase Authentication bootstrap for Murmur Admin.
   No Firebase Admin SDK credentials or Supabase service-role keys belong here. */
(function () {
  "use strict";
  if (!window.firebase || !window.MURMUR_ADMIN_FIREBASE_CONFIG) {
    throw new Error("Firebase SDK or Murmur Admin Firebase configuration is missing.");
  }
  const app = window.firebase.apps.length
    ? window.firebase.app()
    : window.firebase.initializeApp(window.MURMUR_ADMIN_FIREBASE_CONFIG);
  const auth = app.auth();
  auth.setPersistence(window.firebase.auth.Auth.Persistence.LOCAL).catch((error) => {
    console.warn("Could not persist the Admin Firebase session:", error.message);
  });
  window.murmurAdminAuth = auth;
  window.MurmurErrorTokenProvider = () => auth.currentUser
    ? auth.currentUser.getIdToken().catch(() => "")
    : "";
  auth.onAuthStateChanged((user) => {
    if (user && window.MurmurErrors && typeof window.MurmurErrors.flush === "function") {
      window.MurmurErrors.flush();
    }
  });
})();
