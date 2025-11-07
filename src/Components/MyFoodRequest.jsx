import { useContext, useEffect, useState } from "react";
import { motion } from "framer-motion";
import axiosSecure from "../Hooks/axiosSecure";
import Loader from "./Loader";
import AuthContext from "../Provider/AuthContext";

const MyFoodRequest = () => {
    const { user } = useContext(AuthContext);
    const [requests, setRequests] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        axiosSecure
            .get(`/myfoodrequest?email=${user.email}`)
            .then((res) => {
                setRequests(res.data);
                setLoading(false);
            })
            .catch((err) => {
                console.error("Error fetching food requests:", err);
                setLoading(false);
            });
    }, [user]);

    if (loading) return <Loader />;

    return (
        <motion.div
            className="p-6 max-w-7xl mx-auto"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
        >
            <h2 className="text-3xl mt-8 font-extrabold text-green-700 mb-8 text-center">
                My Food Requests
            </h2>

            {requests.length === 0 ? (
                <p className="text-center text-gray-500 text-lg">
                    No food requests found.
                </p>
            ) : (
                <div className="overflow-x-auto mt-10 border border-green-200 shadow-md rounded-lg">
                    <table className="min-w-full table-auto divide-y divide-gray-200 rounded-lg overflow-hidden">
                        <thead className="bg-green-100 text-green-800">
                            <tr>
                                <th className="px-4 py-3 text-sm font-semibold text-center">No.</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Food Name</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Donor Name</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Donor Email</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Pickup Location</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Expire Date</th>
                                <th className="px-4 py-3 text-sm font-semibold text-center">Request Date</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-100">
                            {requests.map((item, index) => (
                                <tr
                                    key={item._id || index}
                                    className="hover:bg-green-50 transition-colors duration-200"
                                >
                                    <td className="px-4 py-3 text-center text-sm text-gray-800">{index + 1}</td>
                                    <td className="px-4 py-3 text-center text-sm text-gray-800">{item.foodName}</td>
                                    <td className="px-4 py-3 text-center text-sm text-gray-800">{item.foodDonatorName}</td>
                                    <td className="px-4 py-3 text-center text-sm text-gray-800">{item.foodDonatorEmail}</td>
                                    <td className="px-4 py-3 text-center text-sm text-gray-800">{item.pickupLocation}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-center text-gray-700">
                                        {new Date(item.expireDate).toLocaleString("en-GB", {
                                            day: "2-digit",
                                            month: "2-digit",
                                            year: "numeric",
                                            hour: "numeric",
                                            minute: "2-digit",
                                            second: "2-digit",
                                            hour12: true,
                                        })}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-center text-gray-700">
                                        {new Date(item.requestDate).toLocaleString("en-GB", {
                                            day: "2-digit",
                                            month: "2-digit",
                                            year: "numeric",
                                            hour: "numeric",
                                            minute: "2-digit",
                                            second: "2-digit",
                                            hour12: true,
                                        })}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </motion.div>
    );
};

export default MyFoodRequest;
