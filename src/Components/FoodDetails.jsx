import React, { useContext, useState } from "react";
import { useLoaderData } from "react-router";
import axios from "axios";
import Swal from "sweetalert2";
import AuthContext from "../Provider/AuthContext";


const FoodDetails = () => {
    const food = useLoaderData();
    const { user } = useContext(AuthContext);

    const [showModal, setShowModal] = useState(false);
    const [additionalNotes, setAdditionalNotes] = useState("");

    if (!food) {
        return <div className="text-center mt-10">Food data not found.</div>;
    }
    const handleRequest = async () => {
        const requestData = {
            foodId: food._id,
            foodName: food.foodName,
            foodImage: food.foodImage,
            foodDonatorName: food.donorName,
            foodDonatorEmail: food.donorEmail,
            userEmail: user?.email || "",
            requestDate: new Date().toISOString(),
            pickupLocation: food.pickupLocation,
            expireDate: food.expiredDateTime,
            additionalNotes,
        };

        try {
            // Update food status to "requested"
            await axios.patch(`https://ass11github.vercel.app/food/${food._id}`, {
                foodStatus: "requested",
            });

            // Save request data in requestedfoods collection
            await axios.post("https://ass11github.vercel.app/requestedfoods", requestData);

            Swal.fire({
                icon: "success",
                title: "Request Submitted",
                text: "Your food request was successful!",
            });

            setShowModal(false);
        } catch (error) {
            console.error("Request error:", error);
            Swal.fire({
                icon: "error",
                title: "Request Failed",
                text: "Something went wrong. Please try again later.",
            });
        }
    };

    return (
        <div className="max-w-3xl mx-auto p-6 bg-gradient-to-br from-white via-slate-100 to-indigo-100 border border-indigo-200 rounded-xl shadow-lg mt-10">



            <img
                src={food.foodImage}
                alt={food.foodName}
                className="w-full h-64 object-cover rounded"
            />
            <h1 className="text-3xl font-bold mt-4">{food.foodName}</h1>
            <p className="text-gray-700 mt-2">
                <strong>Donator Name:</strong> {food.donorName}
            </p>
            <p className="text-gray-700">
                <strong>Donator Email:</strong> {food.donorEmail}
            </p>
            <p className="text-gray-700">
                <strong>Quantity:</strong> {food.foodQuantity}
            </p>
            <p className="text-gray-700">
                <strong>Pickup Location:</strong> {food.pickupLocation}
            </p>
            <p className="text-gray-700">
                <strong>Expiry Date:</strong>{" "}
                {new Date(food.expiredDateTime).toLocaleString()}
            </p>
            <p className="text-gray-700">
                <strong>Status:</strong> {food.foodStatus}
            </p>
            {food.additionalNotes && (
                <p className="text-gray-600 italic mt-2">{food.additionalNotes}</p>
            )}

            <button
                onClick={() => setShowModal(true)}
                className="mt-6 bg-indigo-600 text-white px-5 py-2 cursor-pointer rounded hover:bg-indigo-700"
            >
                Request
            </button>

            {/* Modal */}
            {showModal && (
                <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
                    <div className="bg-white p-6 rounded-lg max-w-lg w-full space-y-4">
                        <h2 className="text-xl font-bold">Request Food</h2>

                        <div className="grid grid-cols-2 gap-4">
                            <label className="block">
                                Food Name
                                <input
                                    type="text"
                                    value={food.foodName}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Food Image URL
                                <input
                                    type="text"
                                    value={food.foodImage}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Food ID
                                <input
                                    type="text"
                                    value={food._id}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Donator Email
                                <input
                                    type="email"
                                    value={food.donorEmail}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Donator Name
                                <input
                                    type="text"
                                    value={food.donorName}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Your Email
                                <input
                                    type="email"
                                    value={user?.email || ""}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Request Date
                                <input
                                    type="text"
                                    value={new Date().toLocaleString()}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Pickup Location
                                <input
                                    type="text"
                                    value={food.pickupLocation}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>

                            <label className="block">
                                Expiry Date
                                <input
                                    type="text"
                                    value={new Date(food.expiredDateTime).toLocaleString()}
                                    disabled
                                    className="input input-bordered w-full bg-gray-100 cursor-not-allowed"
                                />
                            </label>
                        </div>

                        <label className="block">
                            Additional Notes
                            <textarea
                                className="textarea textarea-bordered w-full"
                                rows={3}
                                value={additionalNotes}
                                onChange={(e) => setAdditionalNotes(e.target.value)}
                                placeholder="Add any notes here..."
                            />
                        </label>

                        <div className="flex justify-end gap-4">
                            <button
                                onClick={() => setShowModal(false)}
                                className="btn btn-outline"
                            >
                                Cancel
                            </button>
                            <button onClick={handleRequest} className="btn btn-primary">
                                Request
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default FoodDetails;
