/**
 * This is Raw SQL query for fetching chatrooms by user id
 * The required params are
 * @param userId
 * @param limit
 * @param offset
 */
export const GET_CHATROOMS_BY_USER_ID = `
  SELECT
    c.*,
    chatroom_participants_json.userjson AS participants,
    jsonb_agg(cm.*) as "lastMessage"
  FROM
    chatroom c
    INNER JOIN (
      SELECT
        cpujson."chatroomId" AS "chatroomId",
        jsonb_agg(u.*) AS "userjson",
        array_agg(distinct u.id) as "participantIds"
      FROM
        "user" u
        LEFT JOIN LATERAL (
          SELECT
            cpu."chatroomId" AS "chatroomId",
            array_agg(DISTINCT cpu."userId") AS parts
          FROM
            chatroom_participants_user cpu
          WHERE
            cpu."userId" = u.id
          GROUP BY
            cpu."chatroomId"
        ) AS cpujson ON TRUE
      GROUP BY
        cpujson."chatroomId"
    ) AS chatroom_participants_json ON chatroom_participants_json."chatroomId" = c.id
    INNER JOIN "chat_message" cm on cm.id = c."last-message"
  WHERE
    chatroom_participants_json."participantIds" @> $1 :: uuid []
  GROUP By
    c.id,
    chatroom_participants_json.userjson
  ORDER BY
    c."lastMessageUpdatedAt" DESC
  LIMIT $2 
  OFFSET $3;
`;