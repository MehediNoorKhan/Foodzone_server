import React, { useContext } from "react";
import { useNavigate } from "react-router";
import { toast } from "react-toastify";
import axios from "axios";
import AuthContext from "../Provider/AuthContext";

const SocialLogin = ({ from }) => {
  const navigate = useNavigate();
  const { googleSignIn } = useContext(AuthContext);

  const handleGoogleLogin = () => {
    googleSignIn()
      .then((result) => {
        const user = result.user;

        // Construct user object
        const userInfo = {
          name: user.displayName,
          email: user.email,
          photourl: user.photoURL,
        };

        // Save user info to MongoDB
        axios
          .post("https://ass11github.vercel.app/users", userInfo)
          .then(() => {
            toast.success("Google login successful!");
            navigate(from || "/");
          })
          .catch((err) => {
            console.error("User Save Error:", err.message);
            toast.error("Login successful, but failed to save user info.");
          });
      })
      .catch((error) => {
        console.error("Google Sign-In Error:", error.message);
        toast.error(error.message);
      });
  };

  return (
    <div className="w-full mt-4">
      <div className="flex items-center justify-center my-4">
        <div className="border-t border-gray-300 w-full"></div>
        <span className="mx-4 text-gray-500 text-sm">or</span>
        <div className="border-t border-gray-300 w-full"></div>
      </div>

      <button
        onClick={handleGoogleLogin}
        className="w-full flex items-center justify-center cursor-pointer gap-3 px-4 py-2 border border-gray-300 rounded-md bg-white hover:bg-gray-100 transition duration-200"
      >
        <svg
          aria-label="Google logo"
          width="24"
          height="24"
          viewBox="0 0 533.5 544.3"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            fill="#4285f4"
            d="M533.5 278.4c0-17.4-1.4-34-4-50.2H272v95.1h146.9c-6.4 34.3-25 63.3-53.4 82.8v68h86.2c50.4-46.5 81.8-115.1 81.8-195.7z"
          />
          <path
            fill="#34a853"
            d="M272 544.3c72.6 0 133.6-24 178.2-65.2l-86.2-68c-23.9 16-54.5 25.4-92 25.4-70.7 0-130.5-47.8-151.9-112.1H33.1v70.4A272 272 0 00272 544.3z"
          />
          <path
            fill="#fbbc04"
            d="M120.1 324.4a163 163 0 010-104.6v-70.4H33.1a272 272 0 000 245.4l87-70.4z"
          />
          <path
            fill="#ea4335"
            d="M272 107.1c39.5 0 74.9 13.6 102.8 40.3l77.1-77.1C405.6 24 344.6 0 272 0A272 272 0 0033.1 149.4l87 70.4C141.5 154.9 201.3 107.1 272 107.1z"
          />
        </svg>
        <span className="text-sm font-medium text-gray-700">
          Continue with Google
        </span>
      </button>
    </div>
  );
};

export default SocialLogin;
