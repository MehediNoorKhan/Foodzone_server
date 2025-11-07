import React, { useContext, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import axiosSecure from "../Hooks/axiosSecure.js"; // ✅ Ensure this hook exists// ✅ Adjust to your actual AuthContext path
import { toast } from "react-toastify";
import Swal from "sweetalert2";
import { useNavigate } from "react-router";
import AuthContext from "../Provider/AuthContext.jsx";

const Spinner = () => (
    <div className="flex justify-center items-center h-40">
        <span className="loading loading-spinner loading-lg text-emerald-600"></span>
    </div>
);

const ManageFood = () => {

    const navigate = useNavigate();

    const { user } = useContext(AuthContext);
    const queryClient = useQueryClient();

    const [showUpdateModal, setShowUpdateModal] = useState(false);
    const [currentFood, setCurrentFood] = useState(null);
    const [updateForm, setUpdateForm] = useState({
        foodName: "",
        foodImage: "",
        foodQuantity: "",
        pickupLocation: "",
        expiredDateTime: "",
        additionalNotes: "",
    });

    const { data: foods = [], isLoading } = useQuery({
        queryKey: ["manage-food", user?.email],
        enabled: !!user?.email,
        queryFn: async () => {
            const res = await axiosSecure.get(`/manage-food?email=${user.email}`);
            return res.data;
        },
    });

    const deleteMutation = useMutation({
        mutationFn: async (id) => {
            await axiosSecure.delete(`/food/${id}`);
        },
        onSuccess: (_, id) => {
            toast.success("Food deleted successfully");
            queryClient.setQueryData(["manage-food", user.email], (old) =>
                old.filter((item) => item._id !== id)
            );
        },
        onError: () => toast.error("Failed to delete food"),
    });

    const updateMutation = useMutation({
        mutationFn: async ({ id, updatedData }) => {
            await axiosSecure.put(`/food/${id}`, updatedData);
        },
        onSuccess: (_, { id, updatedData }) => {
            toast.success("Food updated successfully");
            queryClient.setQueryData(["manage-food", user.email], (old) =>
                old.map((item) =>
                    item._id === id ? { ...item, ...updatedData } : item
                )
            );
            setShowUpdateModal(false);
        },
        onError: () => toast.error("Failed to update food"),
    });

    const handleDelete = (id) => {
        Swal.fire({
            title: "Are you sure?",
            text: "You will lose this food entry!",
            icon: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d33",
            cancelButtonColor: "#3085d6",
            confirmButtonText: "Yes, delete it!",
        }).then((result) => {
            if (result.isConfirmed) {
                deleteMutation.mutate(id);
            }
        });
    };

    const openUpdateModal = (food) => {
        setCurrentFood(food);
        setUpdateForm({
            foodName: food.foodName,
            foodImage: food.foodImage,
            foodQuantity: food.foodQuantity,
            pickupLocation: food.pickupLocation,
            expiredDateTime: food.expiredDateTime,
            additionalNotes: food.additionalNotes || "",
        });
        setShowUpdateModal(true);
    };

    const handleUpdateChange = (e) => {
        const { name, value } = e.target;
        setUpdateForm((prev) => ({ ...prev, [name]: value }));
    };

    const handleUpdateSubmit = (e) => {
        e.preventDefault();
        if (!currentFood?._id) return;
        updateMutation.mutate({ id: currentFood._id, updatedData: updateForm });
    };

    if (isLoading) return <Spinner />;

    return (
        <div className="max-w-7xl mx-auto p-4">
            <h1 className="text-3xl font-bold mb-6 mt-8 text-center text-emerald-600">
                Manage Your Foods
            </h1>

            {foods.length === 0 ? (
                <div className="text-center space-y-4">
                    <p className="text-gray-500 text-lg">
                        You haven't added any food yet.
                    </p>
                    <button
                        onClick={() => navigate('/addfood')}
                        className="inline-block cursor-pointer bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-2 px-6 rounded shadow transition duration-300"
                    >
                        Add Food
                    </button>
                </div>
            ) : (
                <div className="overflow-x-auto mt-10 rounded-lg shadow-lg border border-emerald-200">
                    <table className="min-w-full divide-y divide-gray-300 table-auto">
                        <thead className="bg-emerald-600 text-white">
                            <tr className="text-center text-sm uppercase tracking-wider">
                                <th className="py-3 px-4 text-center">No.</th>
                                <th className="py-3 px-4 text-center">Food Name</th>
                                <th className="py-3 px-4 text-center">Quantity</th>
                                <th className="py-3 px-4 text-center">Pickup Location</th>
                                <th className="py-3 px-4 text-center">Expire Date</th>
                                <th className="py-3 px-4 text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {foods.map((food, index) => (
                                <tr
                                    key={food._id}
                                    className={`hover:bg-emerald-50 transition-colors duration-200 ${index !== foods.length - 1 ? 'border-b border-gray-200' : ''
                                        }`}
                                >
                                    <td className="py-3 px-4 text-sm text-center">{index + 1}</td>
                                    <td className="py-3 px-4 text-sm text-center">{food.foodName}</td>
                                    <td className="text-center text-sm text-center">{food.foodQuantity}</td>
                                    <td className="text-center text-sm text-center">{food.pickupLocation}</td>
                                    <td className="text-center text-sm text-center">
                                        {new Date(food.expiredDateTime).toLocaleString("en-GB", {
                                            day: "2-digit",
                                            month: "2-digit",
                                            year: "numeric",
                                            hour: "numeric",
                                            minute: "2-digit",
                                            second: "2-digit",
                                            hour12: true,
                                        })}
                                    </td>
                                    <td className="flex gap-2 pl-1 justify-center py-2">
                                        <button
                                            onClick={() => openUpdateModal(food)}
                                            className="btn btn-xs bg-yellow-400 hover:bg-yellow-500 text-white transition-colors duration-150"
                                        >
                                            Update
                                        </button>
                                        <button
                                            onClick={() => handleDelete(food._id)}
                                            disabled={deleteMutation.isLoading}
                                            className="btn btn-xs bg-red-500 hover:bg-red-600 text-white transition-colors duration-150"
                                        >
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>


            )}

            {/* Update Modal (unchanged) */}
            {showUpdateModal && (
                <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
                    <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
                        <h2 className="text-xl font-semibold mb-4 text-emerald-700">
                            Update Food
                        </h2>
                        <form onSubmit={handleUpdateSubmit} className="space-y-3">
                            {[
                                { label: "Food Name", name: "foodName", type: "text" },
                                { label: "Image URL", name: "foodImage", type: "text" },
                                { label: "Quantity", name: "foodQuantity", type: "number" },
                                {
                                    label: "Pickup Location",
                                    name: "pickupLocation",
                                    type: "text",
                                },
                                {
                                    label: "Expire Date/Time",
                                    name: "expiredDateTime",
                                    type: "datetime-local",
                                    value: new Date(updateForm.expiredDateTime)
                                        .toISOString()
                                        .slice(0, 16),
                                },
                            ].map(({ label, name, type, value }) => (
                                <label key={name} className="block">
                                    <span className="text-sm font-medium">{label}</span>
                                    <input
                                        name={name}
                                        type={type}
                                        value={value ?? updateForm[name]}
                                        onChange={handleUpdateChange}
                                        required
                                        className="input input-bordered w-full mt-1"
                                    />
                                </label>
                            ))}
                            <label className="block">
                                <span className="text-sm font-medium">Additional Notes</span>
                                <textarea
                                    name="additionalNotes"
                                    value={updateForm.additionalNotes}
                                    onChange={handleUpdateChange}
                                    className="textarea textarea-bordered w-full mt-1"
                                />
                            </label>
                            <div className="flex justify-end space-x-3 mt-4">
                                <button
                                    type="button"
                                    className="btn btn-outline"
                                    onClick={() => setShowUpdateModal(false)}
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="btn btn-primary"
                                    disabled={updateMutation.isLoading}
                                >
                                    Update
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ManageFood;
