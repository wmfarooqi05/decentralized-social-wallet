const DEFAULT_PAGE_SIZE = 20;

export const paginationHelper = (
  page?: string,
  pageSize?: string,
): { take: number; skip: number } => {
  let take = 0,
    skip = 0;
  if (pageSize && parseInt(pageSize)) {
    take = parseInt(pageSize);
  }

  if (take && page && parseInt(page)) {
    skip = (parseInt(page) - 1) * take;
  }

  return {
    take,
    skip,
  };
};

export const paginationHelperOffsetLimit = (
  page?: string,
  pageSize?: string,
): { limit: number; offset: number } => {
  const limit = pageSize ? parseInt(pageSize) : DEFAULT_PAGE_SIZE;
  const offset = page ? (parseInt(page) - 1) * limit : 0;

  return {
    limit,
    offset,
  };
};
