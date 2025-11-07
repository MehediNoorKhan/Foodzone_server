import {
    createBrowserRouter,
} from "react-router";
<<<<<<< HEAD
import Home from "../pages/Home";

=======
import RootLayout from "../Components/RootLayout";
import Home from "../Components/Home";
import Login from "../Components/Login";
import Register from "../Components/Register";
import AddFood from "../Components/AddFood";
import PrivateRoute from "../Components/PrivateRoute";
import ManageMyFoods from "../Components/ManageMyFoods";
import AvaialableFoods from "../Components/AvaialableFoods";
import FoodDetails from "../Components/FoodDetails";
import axios from "axios";
import ManageFood from "../Components/ManageFood";
import axiosSecure from "../Hooks/axiosSecure";
import MyFoodRequest from "../Components/MyFoodRequest";
import About from "../Components/About";
import FeaturedFoods from "../Components/FeaturedFoods";
import Membership from "../Components/Membership";
import PaymentSuccess from "../Components/PaymentSuccess";
>>>>>>> 49b60bb8e212443f773b6036832afc20f615267c


export const router = createBrowserRouter([
    {
        path: "/",
        Component: Home,

<<<<<<< HEAD
=======
        children: [
            {
                index: true,
                path: "/",
                Component: Home,

            },
            {
                path: '/about',
                Component: About
            },
            {
                path: "/login",
                Component: Login
            },
            {
                path: "/register",
                Component: Register
            },
            {
                path: '/addfood',
                element: <PrivateRoute><AddFood></AddFood></PrivateRoute>
            },
            {
                path: '/membership',
                element: <PrivateRoute><Membership></Membership></PrivateRoute>
            },
            {
                path: "/membership/success",
                element: <PrivateRoute><PaymentSuccess /></PrivateRoute>,
            },
            {
                path: '/availablefoods',
                Component: AvaialableFoods
            },

            {
                path: '/myfoodrequest',
                element: <PrivateRoute><MyFoodRequest></MyFoodRequest></PrivateRoute>
            },

            {
                path: '/myfoodrequest',
                element: (
                    <PrivateRoute>
                        <MyFoodRequest />
                    </PrivateRoute>
                ),
                loader: async () => {
                    const res = await axiosSecure.get('/myfoodrequest');
                    return res.data;
                }
            },

            {
                path: '/fooddetails/:id',
                element: <PrivateRoute><FoodDetails /></PrivateRoute>,
                loader: async ({ params }) => {
                    try {
                        const res = await axios.get(`https://ass11github.vercel.app/food/${params.id}`);
                        return res.data;
                    } catch (error) {
                        console.error('Error fetching food details:', error);
                        throw new Response('Failed to fetch food details', { status: 500 });
                    }
                },
            },
            {
                path: '/manage-food',
                element: (
                    <PrivateRoute>
                        <ManageFood></ManageFood>
                    </PrivateRoute>
                ),
            },
        ],
>>>>>>> 49b60bb8e212443f773b6036832afc20f615267c
    },
]);
