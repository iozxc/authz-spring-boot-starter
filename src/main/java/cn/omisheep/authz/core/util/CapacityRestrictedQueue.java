package cn.omisheep.authz.core.util;

import java.io.Serializable;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class CapacityRestrictedQueue<E> extends LinkedList<E> implements Deque<E>, Serializable {
    private static final long serialVersionUID = -513422014711150344L;

    private int maxCapacity = 10;

    public CapacityRestrictedQueue() {
        super();
    }

    public CapacityRestrictedQueue(int maxCapacity) {
        super();
        this.maxCapacity = maxCapacity;
    }

    private int overflowCapacity() {
        return Math.max(size() - maxCapacity, 0);
    }

    private void stable(boolean l2b) {
        for (int i = 0; i < overflowCapacity(); i++) {
            if (l2b) {
                pollLast();
            } else {
                pollFirst();
            }
        }
    }

    @Override
    public boolean offer(E e) {
        super.offer(e);
        stable(false);
        return true;
    }

    @Override
    public boolean offerFirst(E e) {
        super.offerFirst(e);
        stable(true);
        return true;
    }

    @Override
    public boolean offerLast(E e) {
        super.offerLast(e);
        stable(false);
        return true;
    }

    @Override
    public void addFirst(E e) {
        super.addFirst(e);
        stable(true);
    }

    @Override
    public void addLast(E e) {
        super.addLast(e);
        stable(false);

    }

    @Override
    public boolean add(E e) {
        super.add(e);
        stable(false);
        return true;
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        super.addAll(c);
        stable(false);
        return true;
    }

    @Override
    public boolean addAll(int index, Collection<? extends E> c) {
        super.addAll(index, c);
        stable(false);
        return true;
    }

    @Override
    public void add(int index, E element) {
        super.add(index, element);
        stable(false);

    }

}

