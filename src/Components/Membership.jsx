import React, { useContext, useEffect, useState } from "react";
import { Elements, CardElement, useStripe, useElements } from "@stripe/react-stripe-js";
import { loadStripe } from "@stripe/stripe-js";
import axios from "axios";
import { toast } from "react-toastify";
import AuthContext from "../Provider/AuthContext";

// Stripe publishable key
const stripePromise = loadStripe("pk_test_51RuFCD2N3HoHVSaoW7VxBVoMp4Wc4REQrh0EnYlar3Ej52hF8hs2Xe1f4BbY7Dfq5AhLPvcHpLSUwVzdVKVPi9lA00F7nQdlAE");

// ----- Checkout Form -----
const CheckoutForm = ({ price, user, onMembershipUpdate }) => {
    const stripe = useStripe();
    const elements = useElements();
    const [clientSecret, setClientSecret] = useState("");
    const [loading, setLoading] = useState(false);
    const [initLoading, setInitLoading] = useState(true);

    useEffect(() => {
        if (!price || !user?.email) return;

        setInitLoading(true);
        axios
            .post("https://ass11github.vercel.app/create-payment-intent", { price })
            .then((res) => setClientSecret(res.data.clientSecret))
            .catch((err) => {
                console.error("Error fetching client secret:", err);
                toast.error("Failed to initialize payment.");
            })
            .finally(() => setInitLoading(false));
    }, [price, user?.email]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!stripe || !elements) return;

        const card = elements.getElement(CardElement);
        if (!card) return;

        setLoading(true);
        try {
            const { error, paymentIntent } = await stripe.confirmCardPayment(clientSecret, {
                payment_method: {
                    card,
                    billing_details: {
                        name: user?.name || "Anonymous",
                        email: user.email,
                    },
                },
            });

            if (error) {
                toast.error(error.message);
                setLoading(false);
                return;
            }

            if (paymentIntent.status === "succeeded") {
                toast.success("Payment Successful 🎉");

                // Update membership in backend
                await axios.patch(`https://ass11github.vercel.app/users/membership/${user.email}`, {
                    membership: "yes",
                });

                toast.success("Your membership is now active!");

                // Update local state immediately
                onMembershipUpdate("yes");
            }
        } catch (err) {
            console.error("Payment error:", err);
            toast.error("Payment failed. Please try again.");
        } finally {
            setLoading(false);
        }
    };

    if (initLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p>Initializing payment...</p>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit} className="max-w-md mx-auto mt-6 p-6 bg-white shadow-md rounded-2xl">
            <CardElement className="border p-4 rounded mb-4" />
            <button
                type="submit"
                disabled={!stripe || !clientSecret || loading}
                className="w-full bg-blue-600 text-white py-2 rounded-md font-semibold hover:bg-blue-700 transition"
            >
                {loading ? "Processing..." : `Pay $${price}`}
            </button>
        </form>
    );
};

// ----- Membership Component -----
const Membership = () => {
    const { user, userData, updateMembership } = useContext(AuthContext);
    const [currentUser, setCurrentUser] = useState(null);
    const [membershipStatus, setMembershipStatus] = useState(null);
    const [loading, setLoading] = useState(true);
    const price = 10;

    useEffect(() => {
        if (!user?.email || !userData) return;

        const foundUser = userData.find((u) => u.email === user.email);
        setCurrentUser(foundUser || null);
        setMembershipStatus(foundUser?.membership || "no");
        setLoading(false);
    }, [user, userData]);

    if (loading || !currentUser) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p>Loading user info...</p>
            </div>
        );
    }

    // Already a member
    if (membershipStatus === "yes") {
        return (
            <div className="min-h-screen flex items-center justify-center px-4">
                <div className="max-w-xl bg-white bg-opacity-90 shadow-2xl rounded-2xl p-8 text-center">
                    <h2 className="text-2xl font-bold text-green-600 mb-4">You're already a member ✅</h2>
                    <p className="text-gray-700">Your membership is active. Enjoy all the benefits!</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-emerald-100 via-white to-indigo-100 flex items-center justify-center px-4 py-12">
            <div className="w-full max-w-xl bg-white bg-opacity-90 shadow-2xl rounded-2xl p-8 backdrop-blur">
                <h2 className="text-2xl font-bold text-red-600 mb-4 text-center">Pay $10 to Become a Member</h2>
                <p className="text-gray-700 mb-4 text-center">After payment, your membership will be activated.</p>
                <Elements stripe={stripePromise}>
                    <CheckoutForm
                        price={price}
                        user={currentUser}
                        onMembershipUpdate={(status) => {
                            setMembershipStatus(status);           // update component immediately
                            updateMembership(currentUser.email, status); // update AuthProvider globally
                        }}
                    />
                </Elements>
            </div>
        </div>
    );
};

export default Membership;
