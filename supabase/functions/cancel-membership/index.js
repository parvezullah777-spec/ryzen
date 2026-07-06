// supabase/functions/cancel-membership/index.ts
// Deploy with: supabase functions deploy cancel-membership
//
// This function cancels a user's Razorpay subscription.
// Called from AuthFlow when user clicks "Cancel membership"

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const RAZORPAY_KEY_ID = Deno.env.get("RAZORPAY_KEY_ID")!;
const RAZORPAY_KEY_SECRET = Deno.env.get("RAZORPAY_KEY_SECRET")!;
const basicAuth = "Basic " + btoa(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`);

Deno.serve(async (req) => {
  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const token = authHeader.replace("Bearer ", "");

    // Verify user is authenticated
    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: authHeader } } }
    );
    const { data: userData, error: userErr } = await userClient.auth.getUser(token);
    if (userErr || !userData.user) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 });
    }

    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Get user's subscription ID from database
    const { data: membership } = await adminClient
      .from("memberships")
      .select("razorpay_subscription_id")
      .eq("user_id", userData.user.id)
      .single();

    if (!membership?.razorpay_subscription_id) {
      return new Response(JSON.stringify({ error: "No active subscription" }), { status: 400 });
    }

    // Cancel subscription with Razorpay
    // cancel_at_cycle_end: 1 means benefits continue until the end of the current paid period
    const res = await fetch(
      `https://api.razorpay.com/v1/subscriptions/${membership.razorpay_subscription_id}/cancel`,
      {
        method: "POST",
        headers: { Authorization: basicAuth, "Content-Type": "application/json" },
        body: JSON.stringify({ cancel_at_cycle_end: 1 }),
      }
    );
    const result = await res.json();
    if (!res.ok) {
      return new Response(JSON.stringify({ error: result.error?.description || "Razorpay error" }), { status: 400 });
    }

    // The webhook will update the status to "cancelled" once Razorpay confirms.
    // We don't update it here to avoid race conditions between the client and webhook.
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 });
  }
});
