import React, { useEffect, useState } from "react";
import axios from "axios";
import { Link } from "react-router";
import "../FeaturedFoods.css";

const FeaturedFoods = () => {
    const [featuredFoods, setFeaturedFoods] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchFoods = async () => {
            try {
                setLoading(true);
                const res = await axios.get("https://ass11github.vercel.app/food");
                setFeaturedFoods(res.data || []);
            } catch (err) {
                console.error("Error fetching featured foods:", err);
                setFeaturedFoods([]); // fallback to empty array
            } finally {
                setLoading(false);
            }
        };

        fetchFoods();
    }, []);

    const getRemainingDays = (expiredDateTime) => {
        if (!expiredDateTime) return 0;
        const today = new Date();
        const exp = new Date(expiredDateTime);

        const t = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const e = new Date(exp.getFullYear(), exp.getMonth(), exp.getDate());

        const diffDays = Math.ceil((e - t) / (1000 * 60 * 60 * 24));
        return diffDays > 0 ? diffDays : 0;
    };

    const validFoods = featuredFoods
        .filter((food) => getRemainingDays(food.expiredDateTime) > 0)
        .slice(0, 8);

    return (
        <section className="bg-green-50">
            <div className="max-w-7xl mx-auto px-4 py-12">
                <h2 className="text-3xl font-bold mb-8 text-center text-[#24725e]">
                    Featured Foods
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-8">
                    {loading
                        ? Array(4)
                            .fill(0)
                            .map((_, idx) => (
                                <div key={idx} className="card animate-pulse">
                                    <div className="card__content">
                                        <span className="card__badge bg-gray-300 text-transparent">
                                            Loading
                                        </span>
                                        <div className="card__image bg-gray-300 h-40 w-full rounded-md" />
                                        <p className="card__title bg-gray-300 text-transparent">
                                            Loading
                                        </p>
                                        <p className="card__description bg-gray-300 text-transparent h-12 mt-2" />
                                        <div className="card__footer">
                                            <button className="card__button cursor-pointer bg-gray-300 text-transparent">
                                                Loading
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            ))
                        : validFoods.map((food) => (
                            <div key={food._id} className="card">
                                <div className="card__content">
                                    <span className="card__badge">
                                        {getRemainingDays(food.expiredDateTime)} days to be expired
                                    </span>

                                    <div className="card__image">
                                        <img src={food.foodImage} alt={food.foodName} />
                                    </div>

                                    <p className="card__title">{food.foodName}</p>

                                    <p className="card__description">
                                        Quantity: {food.foodQuantity}
                                        <br />
                                        Pickup: {food.pickupLocation}
                                    </p>

                                    <div className="card__footer">
                                        <Link to={`/fooddetails/${food._id}`}>
                                            <button className="card__button cursor-pointer">
                                                <span>View Details</span>
                                            </button>
                                        </Link>
                                    </div>
                                </div>
                            </div>
                        ))}
                </div>

                {/* See More Button */}
                <div className="flex justify-center mt-10">
                    <Link to="/availablefoods">
                        <button className="seemorebutton">
                            <span className="button__icon-wrapper">
                                <svg
                                    viewBox="0 0 14 15"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                    width="10"
                                    className="button__icon-svg"
                                >
                                    <path
                                        d="M13.376 11.552l-.264-10.44-10.44-.24.024 2.28 6.96-.048L.2 12.56l1.488 1.488 9.432-9.432-.048 6.912 2.304.024z"
                                        fill="currentColor"
                                    ></path>
                                </svg>

                                <svg
                                    viewBox="0 0 14 15"
                                    fill="none"
                                    width="10"
                                    xmlns="http://www.w3.org/2000/svg"
                                    className="button__icon-svg button__icon-svg--copy"
                                >
                                    <path
                                        d="M13.376 11.552l-.264-10.44-10.44-.24.024 2.28 6.96-.048L.2 12.56l1.488 1.488 9.432-9.432-.048 6.912 2.304.024z"
                                        fill="currentColor"
                                    ></path>
                                </svg>
                            </span>
                            Explore All
                        </button>
                    </Link>
                </div>
            </div>
        </section>
    );
};

export default FeaturedFoods;
