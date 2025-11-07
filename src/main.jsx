import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { RouterProvider } from "react-router";
import { router } from "./Router/Route";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <div>
      <RouterProvider router={router} />
    </div>
    <ToastContainer />
  </StrictMode>
);
