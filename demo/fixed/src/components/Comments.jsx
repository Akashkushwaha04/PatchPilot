import { useEffect, useState } from "react";
import { API_BASE_URL } from "../config";

export default function Comments({ productId }) {
  const [comments, setComments] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/products/${productId}/comments`)
      .then((r) => r.json())
      .then(setComments);
  }, [productId]);

  return (
    <ul className="comments">
      {comments.map((comment) => (
        <li key={comment.id}>
          <strong>{comment.author}</strong>
          <p>{comment.body}</p>
        </li>
      ))}
    </ul>
  );
}
