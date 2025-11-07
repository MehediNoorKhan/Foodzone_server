import React from "react";
import { Link } from "react-router";

const PaymentSuccess = () => {
    return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-green-50 text-center p-6">
            <div className="bg-white shadow-lg rounded-2xl p-10 max-w-md">
                <h2 className="text-3xl font-bold text-green-600 mb-4">
                    Payment Successful 🎉
                </h2>
                <p className="text-gray-700 mb-6">
                    Thank you for your payment. Your membership has been successfully upgraded.
                </p>
                <Link
                    to="/"
                    className="btn btn-primary text-white font-semibold px-6 py-2 rounded-md"
                >
                    Go to Home
                </Link>
            </div>
        </div>
    );
};

export default PaymentSuccess;
