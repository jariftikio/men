import { redirect } from "next/navigation";

/** App Router entry — send `/` to the landing page. */
export default function Home() {
  redirect("/home.html");
}
