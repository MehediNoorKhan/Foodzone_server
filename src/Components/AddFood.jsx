import React, { useContext, useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import AuthContext from "../Provider/AuthContext";

const AddFood = () => {
    const { user, userData, loading: authLoading, fetchError } = useContext(AuthContext);

    const [currentUser, setCurrentUser] = useState(null);
    const [postCount, setPostCount] = useState(0);
    const [loading, setLoading] = useState(true);
    const [formData, setFormData] = useState({
        foodName: "",
        foodImage: "",
        foodQuantity: "",
        pickupLocation: "",
        expiredDateTime: "",
        additionalNotes: "",
    });

    const maxPostsAllowed = 5;

    // Fetch current user and post count
    useEffect(() => {
        if (!user || !userData) return;

        const foundUser = userData.find((u) => u.email === user.email);
        setCurrentUser(foundUser || null);

        if (foundUser) {
            setLoading(true);
            axios
                .get(`https://ass11github.vercel.app/food/count/${user.email}`)
                .then((res) => setPostCount(res.data.count || 0))
                .catch((err) => {
                    console.error("Failed to fetch food count:", err);

                })
                .finally(() => setLoading(false));
        } else {
            setLoading(false);
        }
    }, [user, userData]);

    const handleChange = (e) =>
        setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value }));

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!currentUser) return;

        const newFood = {
            ...formData,
            foodQuantity: Number(formData.foodQuantity),
            donorName: currentUser.name,
            donorEmail: currentUser.email,
            donorImage: currentUser.photourl,
            foodStatus: "available",
        };

        try {
            const res = await axios.post("https://ass11github.vercel.app/food", newFood);
            if (res.data.insertedId) {
                toast.success("Food added successfully!");
                setFormData({
                    foodName: "",
                    foodImage: "",
                    foodQuantity: "",
                    pickupLocation: "",
                    expiredDateTime: "",
                    additionalNotes: "",
                });
                setPostCount((prev) => prev + 1); // instant update
            }
        } catch (err) {
            console.error(err);
            toast.error("Failed to add food. Please try again.");
        }
    };

    // Wait until user, currentUser, and postCount are ready
    if (authLoading || loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p>Loading your info...</p>
            </div>
        );
    }

    if (fetchError) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p className="text-red-600">{fetchError}</p>
            </div>
        );
    }

    if (!currentUser) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p className="text-red-600">There is no user</p>
            </div>
        );
    }

    const canPost = postCount < maxPostsAllowed || currentUser.membership === "yes";

    return (
        <div className="min-h-screen bg-gradient-to-br from-emerald-100 via-white to-indigo-100 flex items-center justify-center px-4 py-12">
            <div className="w-full max-w-xl bg-white bg-opacity-90 shadow-2xl rounded-2xl p-8 backdrop-blur">
                <h2 className="text-3xl font-bold text-center text-indigo-700 mb-8">Add Food</h2>

                {canPost ? (
                    <>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div>
                                <label className="block font-medium">Food Name</label>
                                <input
                                    type="text"
                                    name="foodName"
                                    value={formData.foodName}
                                    onChange={handleChange}
                                    required
                                    className="input input-bordered w-full"
                                />
                            </div>
                            <div>
                                <label className="block font-medium">Food Image URL</label>
                                <input
                                    type="text"
                                    name="foodImage"
                                    value={formData.foodImage}
                                    onChange={handleChange}
                                    required
                                    className="input input-bordered w-full"
                                    placeholder="Image URL"
                                />
                            </div>
                            <div>
                                <label className="block font-medium">Food Quantity</label>
                                <input
                                    type="number"
                                    name="foodQuantity"
                                    value={formData.foodQuantity}
                                    onChange={handleChange}
                                    required
                                    className="input input-bordered w-full"
                                    placeholder="e.g., 5"
                                />
                            </div>
                            <div>
                                <label className="block font-medium">Pickup Location</label>
                                <input
                                    type="text"
                                    name="pickupLocation"
                                    value={formData.pickupLocation}
                                    onChange={handleChange}
                                    required
                                    className="input input-bordered w-full"
                                />
                            </div>
                            <div>
                                <label className="block font-medium">Expired Date/Time</label>
                                <input
                                    type="datetime-local"
                                    name="expiredDateTime"
                                    value={formData.expiredDateTime}
                                    onChange={handleChange}
                                    required
                                    className="input input-bordered w-full"
                                />
                            </div>
                            <div>
                                <label className="block font-medium">Additional Notes</label>
                                <textarea
                                    name="additionalNotes"
                                    value={formData.additionalNotes}
                                    onChange={handleChange}
                                    className="textarea textarea-bordered w-full"
                                    placeholder="Any extra info (optional)"
                                />
                            </div>
                            <button
                                type="submit"
                                className="btn btn-primary w-full tracking-wide font-semibold text-white"
                            >
                                Add Food
                            </button>
                        </form>
                    </>
                ) : (
                    <div className="text-center">
                        <h2 className="text-2xl font-bold text-red-600 mb-4">Membership Required</h2>
                        <p className="text-gray-700 mb-4">
                            You have reached your allowed number of food posts ({postCount}/{maxPostsAllowed}).
                        </p>
                        <p className="text-gray-600 mb-4">Upgrade your membership to add more posts.</p>
                        <button
                            onClick={() => (window.location.href = "/membership")}
                            className="bg-blue-600 text-white py-2 px-6 rounded-md font-semibold hover:bg-blue-700 transition"
                        >
                            Be a Member
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AddFood;
