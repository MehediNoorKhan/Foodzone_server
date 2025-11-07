import React, { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router";
import Loader from "./Loader";

const AvailableFoods = () => {
    const [foods, setFoods] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isThreeCol, setIsThreeCol] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortOrder, setSortOrder] = useState("");
    const navigate = useNavigate();

    useEffect(() => {
        const delayDebounce = setTimeout(() => {
            setLoading(true);
            axios
                .get("https://ass11github.vercel.app/food", {
                    params: { search: searchTerm, sortOrder },
                })
                .then((res) => {
                    const today = new Date();
                    // ✅ Filter out expired foods on the frontend as backup
                    const availableFoods = res.data.filter(food => new Date(food.expiredDateTime) > today);
                    setFoods(availableFoods);
                })
                .catch((err) => console.error("Error fetching foods:", err))
                .finally(() => setLoading(false));
        }, 500);

        return () => clearTimeout(delayDebounce);
    }, [searchTerm, sortOrder]);

    const gridColsClass = isThreeCol
        ? "grid-cols-1 sm:grid-cols-2 md:grid-cols-3"
        : "grid-cols-1 sm:grid-cols-2 md:grid-cols-2";

    return (
        <div className="max-w-7xl mx-auto px-4 py-16">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-8">
                <h1 className="text-4xl font-extrabold text-indigo-700 tracking-tight">
                    Available Foods
                </h1>

                <div className="flex flex-col sm:flex-row gap-4 w-full sm:w-auto items-center">
                    <input
                        type="text"
                        placeholder="Search food by name..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="input input-bordered w-full sm:w-64"
                    />

                    <select
                        value={sortOrder}
                        onChange={(e) => setSortOrder(e.target.value)}
                        className="cursor-pointer input input-bordered w-full sm:w-auto"
                    >
                        <option value="" disabled>Sort By</option>
                        <option value="desc">Newest &#x25BC;</option>
                        <option value="asc">Oldest &#x25B2;</option>
                    </select>

                    <div className="inline-flex rounded-lg overflow-hidden border border-gray-400">
                        <button
                            onClick={() => setIsThreeCol(true)}
                            className={`px-4 py-2 text-sm cursor-pointer font-medium transition-colors duration-300 ${isThreeCol ? "bg-indigo-600 text-white" : "bg-white text-gray-700"}`}
                        >
                            3 Column View
                        </button>
                        <button
                            onClick={() => setIsThreeCol(false)}
                            className={`px-4 py-2 text-sm cursor-pointer font-medium transition-colors duration-300 ${!isThreeCol ? "bg-orange-500 text-white" : "bg-white text-gray-700"}`}
                        >
                            2 Column View
                        </button>
                    </div>
                </div>
            </div>

            {loading ? (
                <Loader />
            ) : foods.length === 0 ? (
                <p className="text-center text-gray-500 text-lg">
                    No available foods found.
                </p>
            ) : (
                <div className={`grid ${gridColsClass} gap-8`}>
                    {foods.map((food) => (
                        <div
                            key={food._id}
                            className="bg-white rounded-xl shadow-lg overflow-hidden transform transition duration-300 hover:scale-[1.03] hover:shadow-2xl flex flex-col"
                        >
                            <div className="relative h-48">
                                <img
                                    src={food.foodImage}
                                    alt={food.foodName}
                                    className="w-full h-full object-cover"
                                />
                                <span className="absolute top-2 right-2 bg-green-500 text-white px-3 py-1 rounded-full text-xs font-semibold shadow-md">
                                    Available
                                </span>
                            </div>
                            <div className="p-6 flex flex-col flex-grow">
                                <h2 className="text-xl font-bold text-gray-800 mb-2">
                                    {food.foodName}
                                </h2>
                                <p className="text-gray-600 mb-1">
                                    <strong>Quantity:</strong> {food.foodQuantity}
                                </p>
                                <p className="text-gray-600 mb-1">
                                    <strong>Pickup Location:</strong> {food.pickupLocation}
                                </p>
                                <p className="text-gray-600 mb-3">
                                    <strong>Expires:</strong>{" "}
                                    {new Date(food.expiredDateTime).toLocaleString(undefined, {
                                        dateStyle: "medium",
                                        timeStyle: "short",
                                    })}
                                </p>
                                {food.additionalNotes && (
                                    <p className="text-gray-500 italic mb-4 flex-grow">
                                        {food.additionalNotes}
                                    </p>
                                )}
                                <button
                                    onClick={() => navigate(`/fooddetails/${food._id}`)}
                                    className="mt-auto bg-indigo-600 text-white cursor-pointer font-semibold py-2 rounded-lg hover:bg-indigo-700 transition"
                                >
                                    View Details
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default AvailableFoods;
